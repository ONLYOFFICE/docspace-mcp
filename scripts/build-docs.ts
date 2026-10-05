import * as fs from "node:fs/promises"
import * as mcp from "../lib/mcp.ts"
import type * as utilMcp from "../lib/util/mcp.ts"
import * as tools from "./tools.ts"

/**
 * {@link https://docs.cursor.com/en/tools/developers#mcp-servers | Cursor Reference}
 */
type CursorQuery = {
  name: string
  config: string
}

type VscodeQuery = {
  name: string
  inputs: string
  config: string
  quality?: string
}

/**
 * {@link https://code.visualstudio.com/docs/reference/variables-reference/#_input-variables | VS Code Reference}
 */
type VscodeInput = {
  type: string
  id: string
  description: string
  password?: boolean
}

/**
 * {@link https://code.visualstudio.com/docs/copilot/chat/mcp-servers/#_configuration-format | VS Code Reference}
 */
type Config = {
  command: string
  args: string[]
  env: ConfigEnv
}

// todo: use envPrefix var from lib/config.ts
type ConfigEnv = {
  DOCSPACE_BASE_URL: string
  DOCSPACE_API_KEY: string
}

async function main(): Promise<void> {
  await Promise.all([
    updateTools("docs/reference/tools.md"),
    updateQuickInstall("docs/getting-started/installation.md"),
  ])
}

async function updateTools(f: string): Promise<void> {
  let s = await fs.readFile(f, "utf8")

  let toolsets = tools.sortToolsets(mcp.regularToolsets)
  let metaTools = tools.sortTools(mcp.metaTools)

  let o = createToolsetsTable(toolsets)
  s = insert("toolsets", s, o)

  let m = createMetaToolsTable(metaTools)
  s = insert("meta-tools", s, m)

  let t = createToolsTable(toolsets)
  s = insert("tools", s, t)

  await fs.writeFile(f, s, "utf8")
}

async function updateQuickInstall(f: string): Promise<void> {
  let s = await fs.readFile(f, "utf8")

  let t = createQuickInstallTable()
  s = insert("quick-install", s, t)

  await fs.writeFile(f, s, "utf8")
}

function createQuickInstallTable(): string {
  let c = ""
  let b = ""
  let i = ""
  let x = ""
  let y = ""

  i = createBadgenLink("Cursor", "black")
  x = createCursorDockerImageLink()
  x = createMarkdownBadge("Add to Cursor using Docker Image", i, x)
  y = createCursorNpxLink()
  y = createMarkdownBadge("Add to Cursor using npx", i, y)
  b += `| ${x} | ${y} |\n`

  i = createBadgenLink("VS Code", "blue")
  x = createVscodeDockerImageLink()
  x = createMarkdownBadge("Add to VS Code using Docker Image", i, x)
  y = createVscodeNpxLink()
  y = createMarkdownBadge("Add to VS Code using npx", i, y)
  b += `| ${x} | ${y} |\n`

  i = createBadgenLink("VS Code Insiders", "cyan")
  x = createVscodeInsidersDockerImageLink()
  x = createMarkdownBadge("Add to VS Code Insiders using Docker Image", i, x)
  y = createVscodeInsidersNpxLink()
  y = createMarkdownBadge("Add to VS Code Insiders using npx", i, y)
  b += `| ${x} | ${y} |\n`

  b = b.slice(0, -1)

  let h = "| Docker Image | Node.js Application |\n|:-:|:-:|"
  c = `${h}\n${b}`

  return c
}

function createBadgenLink(n: string, c: string): string {
  let s = `https://badgen.net/static/Add to/${n}/${c}`
  let u = new URL(s)
  return u.toString()
}

function createMarkdownBadge(l: string, i: string, a: string): string {
  return `[![${l}](${i})](${a})`
}

function createCursorDockerImageLink(): string {
  let e = createSharedConfigEnv()
  let c = createDockerImageConfig(e)
  let q = createCursorQuery(c)
  let u = createCursorLink(q)
  return u
}

function createCursorNpxLink(): string {
  let e = createSharedConfigEnv()
  let c = createNpxConfig(e)
  let q = createCursorQuery(c)
  let u = createCursorLink(q)
  return u
}

function createCursorQuery(c: Config): CursorQuery {
  return {
    name: "onlyoffice-apps",
    config: Buffer.from(JSON.stringify(c)).toString("base64"),
  }
}

function createCursorLink(q: CursorQuery): string {
  let s = "https://cursor.com/en/install-mcp"
  let u = new URL(s)
  let p = new URLSearchParams(q)
  u.search = p.toString()
  return u.toString()
}

function createVscodeDockerImageLink(): string {
  let i = createVscodeInputs()
  let e = createVscodeConfigEnv()
  let c = createDockerImageConfig(e)
  let q = createVscodeQuery(i, c)
  let u = createVscodeLink(q)
  return u
}

function createVscodeNpxLink(): string {
  let i = createVscodeInputs()
  let e = createSharedConfigEnv()
  let c = createNpxConfig(e)
  let q = createVscodeQuery(i, c)
  let u = createVscodeLink(q)
  return u
}

function createVscodeInsidersDockerImageLink(): string {
  let i = createVscodeInputs()
  let e = createVscodeConfigEnv()
  let c = createDockerImageConfig(e)
  let q = createVscodeInsidersQuery(i, c)
  let u = createVscodeLink(q)
  return u
}

function createVscodeInsidersNpxLink(): string {
  let i = createVscodeInputs()
  let e = createSharedConfigEnv()
  let c = createNpxConfig(e)
  let q = createVscodeInsidersQuery(i, c)
  let u = createVscodeLink(q)
  return u
}

function createVscodeInputs(): VscodeInput[] {
  return [
    {
      type: "promptString",
      id: "docspace_base_url",
      description: "The base URL of the ONLYOFFICE Apps instance for API requests.",
    },
    {
      type: "promptString",
      id: "docspace_api_key",
      description: "The API key for accessing the ONLYOFFICE Apps API.",
      password: true,
    },
  ]
}

function createVscodeConfigEnv(): ConfigEnv {
  return {
    DOCSPACE_BASE_URL: "${input:docspace_base_url}",
    DOCSPACE_API_KEY: "${input:docspace_api_key}",
  }
}

function createVscodeInsidersQuery(i: VscodeInput[], c: Config): VscodeQuery {
  let q = createVscodeQuery(i, c)
  q.quality = "insiders"
  return q
}

function createVscodeQuery(i: VscodeInput[], c: Config): VscodeQuery {
  return {
    name: "onlyoffice-apps",
    inputs: JSON.stringify(i),
    config: JSON.stringify(c),
  }
}

function createVscodeLink(q: VscodeQuery): string {
  let s = "https://insiders.vscode.dev/redirect/mcp/install"
  let u = new URL(s)
  let p = new URLSearchParams(q)
  u.search = p.toString()
  return u.toString()
}

function createSharedConfigEnv(): ConfigEnv {
  return {
    DOCSPACE_BASE_URL: "https://your-instance.onlyoffice.com",
    DOCSPACE_API_KEY: "your-api-key",
  }
}

function createDockerImageConfig(e: ConfigEnv): Config {
  return {
    command: "docker",
    args: [
      "run",
      "--interactive",
      "--rm",
      "--env",
      "DOCSPACE_BASE_URL",
      "--env",
      "DOCSPACE_API_KEY",
      "onlyoffice/docspace-mcp",
    ],
    env: e,
  }
}

function createNpxConfig(e: ConfigEnv): Config {
  return {
    command: "npx",
    args: ["--yes", "@onlyoffice/docspace-mcp"],
    env: e,
  }
}

const toolsetNotes: Record<string, string> = {
  files: "> **Note:** Supported file formats for uploading: `txt`, `md`.",
}

function createToolsetsTable(toolsets: utilMcp.Toolset[]): string {
  let r: string[][] = []

  for (let [i, t] of toolsets.entries()) {
    r.push([String(i + 1), `\`${t.name}\``, t.description])
  }

  if (r.length === 0) {
    throw new Error("Toolsets table is empty")
  }

  return createMarkdownTable(["#", "Toolset Name", "Toolset Description"], r)
}

function createToolsTable(toolsets: utilMcp.Toolset[]): string {
  let c: string[] = []

  let i = 0

  for (let s of toolsets) {
    let r: string[][] = []

    for (let [j, t] of s.tools.entries()) {
      r.push([String(j + 1 + i), `\`${t.name}\``, t.description])
    }

    if (r.length !== 0) {
      let n = s.name[0].toUpperCase() + s.name.slice(1)
      let b = `### ${n} toolset\n\n${createMarkdownTable(["#", "Tool Name", "Tool Description"], r)}`

      let o = toolsetNotes[s.name]
      if (o) {
        b += `\n\n${o}`
      }

      c.push(b)
    }

    i += s.tools.length
  }

  if (c.length === 0) {
    throw new Error("Tools table is empty")
  }

  return c.join("\n\n")
}

function createMetaToolsTable(tools: utilMcp.ToolSummary[]): string {
  let r: string[][] = []

  for (let [i, t] of tools.entries()) {
    r.push([String(i + 1), `\`${t.name}\``, t.description])
  }

  if (r.length === 0) {
    throw new Error("Meta tools table is empty")
  }

  return createMarkdownTable(["#", "Meta Tool Name", "Meta Tool Description"], r)
}

function createMarkdownTable(h: string[], r: string[][]): string {
  let w: number[] = []
  let d: string[] = []

  for (let [i, c] of h.entries()) {
    let m = Math.max(3, c.length)
    for (let l of r) {
      m = Math.max(m, l[i].length)
    }
    w.push(m)
    d.push("-".repeat(m))
  }

  let f = (l: string[]): string => {
    let p: string[] = []
    for (let [i, c] of l.entries()) {
      p.push(c.padEnd(w[i]))
    }
    return `| ${p.join(" | ")} |`
  }

  let c = [f(h), f(d)]

  for (let l of r) {
    c.push(f(l))
  }

  return c.join("\n")
}

function insert(s: string, c: string, p: string): string {
  let b: string[] = []

  let inside = false
  let found = false

  for (let l of c.split("\n")) {
    if (l === `<!--generate ${s}-start-->`) {
      inside = true
      found = true
      b.push(l)
      b.push("")
      b.push(p)
      b.push("")
      continue
    }

    if (l === `<!--generate ${s}-end-->` && inside) {
      inside = false
      b.push(l)
      continue
    }

    if (!inside) {
      b.push(l)
      continue
    }
  }

  if (!found) {
    throw new Error(`Section ${s} not found`)
  }

  return b.join("\n")
}

await main()
