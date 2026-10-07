/**
 * @module
 * @mergeModuleWith office-api
 */

import * as r from "../util/result.ts"

export const defaultBaseUrl = "https://api.onlyoffice.com/docs/office-api/usage-api/"

export const defaultTtl = 24 * 60 * 60 * 1000 // 24 hours

export const editors = ["document", "spreadsheet", "presentation", "form", "pdf"] as const

export type Editor = typeof editors[number]

export type ReferenceEntryKind = "overview" | "class" | "method" | "enumeration"

export type ReferenceEntry = {
  kind: ReferenceEntryKind
  name: string
  description: string
  url: string
}

export type ReferenceConfig = {
  baseUrl: string
  userAgent: string
  ttl: number
  fetch: typeof globalThis.fetch
}

type Cached<T> = {
  value: T
  expires: number
}

const maxPages = 500

// An entry of an index: "- [ApiParagraph.AddText](https://...): Adds some text."
const entryLine = /^- \[([^\]]+)\]\((\S+?)\): ?(.*)$/

const sectionLine = /^## (.+)$/

// A link to another page of the reference, which costs more than the name it
// carries and points to a page that can be asked for by name.
const referenceLink = /\[([^\]]*)\]\(https:\/\/api\.onlyoffice\.com\/[^)\s]*\)/g

const frontMatter = /^---\r?\n[\s\S]*?\r?\n---\r?\n/

/**
 * Reads the Office JavaScript API reference published at api.onlyoffice.com
 * as Markdown. Pages are only ever requested by the addresses listed in the
 * index of an editor, and both indexes and pages are cached in memory.
 */
export class Reference {
  private baseUrl: string
  private userAgent: string
  private ttl: number
  private fetch: typeof globalThis.fetch

  private indexes = new Map<Editor, Cached<ReferenceEntry[]>>()
  private pages = new Map<string, Cached<string>>()

  constructor(config: ReferenceConfig) {
    this.baseUrl = config.baseUrl
    this.userAgent = config.userAgent
    this.ttl = config.ttl
    this.fetch = config.fetch
  }

  async index(e: Editor): Promise<r.Result<ReferenceEntry[], Error>> {
    let c = this.indexes.get(e)
    if (c && c.expires > Date.now()) {
      return r.ok(c.value)
    }

    let u = r.safeNew(URL, `${e}-api/llms.txt`, this.baseUrl)
    if (u.err) {
      return r.error(new Error("Creating URL.", {cause: u.err}))
    }

    let t = await this.get(u.v.toString())
    if (t.err) {
      return r.error(new Error("Getting index.", {cause: t.err}))
    }

    let a = parseIndex(t.v)
    if (a.length === 0) {
      return r.error(new Error(`Index of the ${e} editor has no entries.`))
    }

    this.indexes.set(e, {value: a, expires: Date.now() + this.ttl})

    return r.ok(a)
  }

  async page(en: ReferenceEntry): Promise<r.Result<string, Error>> {
    let c = this.pages.get(en.url)
    if (c && c.expires > Date.now()) {
      return r.ok(c.value)
    }

    // The index is fetched over the network, so an address in it is not
    // trusted to lead anywhere but the reference itself. Both addresses are
    // compared once resolved, so that dot segments cannot step out of it.
    let b = r.safeNew(URL, this.baseUrl)
    if (b.err) {
      return r.error(new Error("Parsing base URL.", {cause: b.err}))
    }

    let u = r.safeNew(URL, en.url)
    if (u.err) {
      return r.error(new Error("Parsing page URL.", {cause: u.err}))
    }

    if (!u.v.href.startsWith(b.v.href)) {
      return r.error(new Error(`Page ${en.url} is outside of the reference.`))
    }

    let t = await this.get(u.v.href)
    if (t.err) {
      return r.error(new Error("Getting page.", {cause: t.err}))
    }

    let v = t.v.replace(frontMatter, "").replace(referenceLink, "$1").trim()

    if (this.pages.size >= maxPages) {
      for (let k of this.pages.keys()) {
        this.pages.delete(k)
        break
      }
    }

    this.pages.set(en.url, {value: v, expires: Date.now() + this.ttl})

    return r.ok(v)
  }

  private async get(u: string): Promise<r.Result<string, Error>> {
    let h: Record<string, string> = {
      Accept: "text/markdown, text/plain",
    }

    if (this.userAgent) {
      h["User-Agent"] = this.userAgent
    }

    let req = r.safeNew(Request, u, {headers: h})
    if (req.err) {
      return r.error(new Error("Creating request.", {cause: req.err}))
    }

    let res = await r.safeAsync(this.fetch, req.v)
    if (res.err) {
      return r.error(new Error("Fetching request.", {cause: res.err}))
    }

    if (!res.v.ok) {
      return r.error(new Error(`GET ${u}: ${res.v.status} ${res.v.statusText}`))
    }

    let t = await r.safeAsync(res.v.text.bind(res.v))
    if (t.err) {
      return r.error(new Error("Reading response.", {cause: t.err}))
    }

    return r.ok(t.v)
  }
}

/**
 * Finds the entry with the name, preferring the exact spelling and falling
 * back to one that differs in case only.
 */
export function findEntry(a: ReferenceEntry[], n: string, k: ReferenceEntryKind[]): ReferenceEntry | undefined {
  let l = n.toLowerCase()
  let f: ReferenceEntry | undefined

  for (let e of a) {
    if (!k.includes(e.kind)) {
      continue
    }

    if (e.name === n) {
      return e
    }

    if (!f && e.name.toLowerCase() === l) {
      f = e
    }
  }

  return f
}

/**
 * Finds the classes, methods and enumerations whose name and description hold
 * every word of the query, those that hold them in the name first.
 */
export function searchEntries(a: ReferenceEntry[], q: string): ReferenceEntry[] {
  let w = q.toLowerCase().split(/\s+/).filter((s) => s !== "")
  if (w.length === 0) {
    return []
  }

  let x: ReferenceEntry[] = []
  let y: ReferenceEntry[] = []

  for (let e of a) {
    if (e.kind === "overview") {
      continue
    }

    let n = e.name.toLowerCase()
    let t = `${n} ${e.description.toLowerCase()}`

    if (w.every((s) => n.includes(s))) {
      x.push(e)
    } else if (w.every((s) => t.includes(s))) {
      y.push(e)
    }
  }

  return [...x, ...y]
}

/**
 * Explains that a class, an enumeration or a method is missing from an index
 * and names what can be asked for instead: the methods of the class, or the
 * classes and enumerations with similar names.
 */
export function notFoundMessage(a: ReferenceEntry[], ed: Editor, c: string, m?: string): string {
  if (m !== undefined) {
    let ce = findEntry(a, c, ["class"])

    if (ce) {
      let p = `${ce.name}.`
      let n: string[] = []

      for (let e of a) {
        if (e.kind === "method" && e.name.startsWith(p)) {
          n.push(e.name.slice(p.length))
        }
      }

      return `The ${ce.name} class of the ${ed} API has no ${m} method. Its methods are: ${n.join(", ")}.`
    }
  }

  let l = c.toLowerCase()
  let s: string[] = []

  for (let e of a) {
    if ((e.kind === "class" || e.kind === "enumeration") && e.name.toLowerCase().includes(l)) {
      s.push(e.name)
    }
  }

  let t = `The ${ed} API has no ${c} class or enumeration.`

  if (s.length !== 0) {
    t += ` Similar names: ${s.slice(0, 20).join(", ")}.`
  } else {
    t += " Call the tool without class for the list of classes, or with query to search."
  }

  return t
}

export function parseIndex(t: string): ReferenceEntry[] {
  let a: ReferenceEntry[] = []
  let s = ""

  for (let l of t.split(/\r?\n/)) {
    let m = sectionLine.exec(l)
    if (m) {
      s = m[1].trim()
      continue
    }

    m = entryLine.exec(l)
    if (!m) {
      continue
    }

    let [, n, u, d] = m

    let k: ReferenceEntryKind

    if (s === "Overview") {
      k = "overview"
    } else if (s === "Enumeration") {
      k = "enumeration"
    } else if (n.includes(".")) {
      k = "method"
    } else {
      k = "class"
    }

    a.push({kind: k, name: n, description: d.trim(), url: u})
  }

  return a
}
