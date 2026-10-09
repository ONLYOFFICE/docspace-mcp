/**
 * @module test
 */

import assert from "node:assert/strict"
import childProcess from "node:child_process"
import http from "node:http"
import net from "node:net"
import querystring from "node:querystring"
import type test from "node:test"
import * as client from "@modelcontextprotocol/sdk/client/index.js"
import * as sse from "@modelcontextprotocol/sdk/client/sse.js"
import * as stdio from "@modelcontextprotocol/sdk/client/stdio.js"
import * as streamableHttp from "@modelcontextprotocol/sdk/client/streamableHttp.js"
import type * as transport from "@modelcontextprotocol/sdk/shared/transport.js"
import type * as types from "@modelcontextprotocol/sdk/types.js"
import * as r from "../lib/util/result.ts"

export type AsyncRequestListener = (...args: Parameters<http.RequestListener>) => PromiseLike<void> | void

export class Deferred {
  private p: Promise<void>
  private res: () => void = () => {}
  private rej: (err: Error) => void = () => {}
  private ca: (() => void)[] = []

  get promise(): Promise<void> {
    return this.p
  }

  constructor() {
    const e = (res: () => void, rej: (err: Error) => void): void => {
      this.res = res
      this.rej = rej
    }

    this.p = new Promise<void>(e)
  }

  resolve(): void {
    this.res()
  }

  reject(err: Error): void {
    this.rej(err)
  }

  withTimeout(t: number, m: string): void {
    const f = (): void => {
      this.rej(new DOMException(m, "AbortError"))
    }

    const s = setTimeout(f, t)

    const c = (): void => {
      clearTimeout(s)
    }

    this.ca.push(c)
  }

  clear(): void {
    for (const c of this.ca) {
      c()
    }
  }
}

export function inDelta(a: number, e: number, d: number): boolean {
  return Math.abs(e - a) <= d
}

export function isUuid(s: string): boolean {
  return /^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/.test(s)
}

export async function onRequest(t: test.TestContext, s: http.Server, l: AsyncRequestListener): Promise<void> {
  const e = (_: unknown, reject: (err: Error) => void): void => {
    const onRequest: http.RequestListener = (req, res) => {
      void (async() => {
        try {
          await l(req, res)
        } catch (err) {
          res.destroy()
          if (err instanceof Error) {
            reject(err)
          } else {
            reject(new Error("Non-Error thrown", {cause: err}))
          }
        }
      })()
    }

    const onAfter: test.TestContextHookFn = () => {
      s.removeListener("request", onRequest)
    }

    t.after(onAfter)

    s.addListener("request", onRequest)
  }

  await new Promise(e)
}

export function once<R>(fn: () => R): typeof fn {
  let f = false
  let r: R
  return (): R => {
    if (!f) {
      f = true
      r = fn()
    }
    return r
  }
}

export function parseFetchLocation(res: Response): r.Result<URL, Error> {
  const s = res.headers.get("Location")
  if (!s) {
    return r.error(new Error("Location is missing"))
  }

  const u = r.safeNew(URL, s)
  if (u.err) {
    return r.error(new Error("Parsing URL", {cause: u.err}))
  }

  return r.ok(u.v)
}

export function powerSet<T>(arr: T[]): T[][] {
  const x: T[][] = []

  for (let i = 0; i < Math.pow(2, arr.length); i += 1) {
    const y: T[] = []

    for (const [j, e] of arr.entries()) {
      if (i >> j & 1) {
        y.push(e)
      }
    }

    x.push(y)
  }

  return x
}

export async function randomAddress(): Promise<r.Result<net.AddressInfo, Error>> {
  const s = new net.Server()

  let e = (res: (v: r.Result<void, Error>) => void): void => {
    const onError = (err: Error): void => {
      res(r.error(err))
    }

    const onListening = (): void => {
      res(r.ok())
    }

    s.once("error", onError)
    s.once("listening", onListening)
  }

  const p = new Promise(e)

  const listen: (port: number, host: string) => net.Server = s.listen.bind(s)

  const l = r.safeSync(listen, 0, "::")
  if (l.err) {
    return r.error(new Error("Listening server", {cause: l.err}))
  }

  let w = await p
  if (w.err) {
    return r.error(new Error("Waiting for server", {cause: w.err}))
  }

  const a = s.address()

  if (!a || typeof a !== "object") {
    return r.error(new Error("Address is not object"))
  }

  e = (res) => {
    const onClose = (err: Error | undefined): void => {
      if (err) {
        res(r.error(err))
      } else {
        res(r.ok())
      }
    }

    s.close(onClose)
  }

  w = await new Promise(e)
  if (w.err) {
    return r.error(new Error("Closing server", {cause: w.err}))
  }

  return r.ok(a)
}

export async function readFetchJson(res: Response): Promise<r.Result<unknown, Error>> {
  const t = res.headers.get("Content-Type")

  if (!t) {
    return r.error(new Error("Content-Type is missing"))
  }

  if (t !== "application/json; charset=utf-8") {
    return r.error(new Error(`Content-Type ${t} is not 'application/json; charset=utf-8'`))
  }

  const l = res.headers.get("Content-Length")

  if (!l) {
    return r.error(new Error("Content-Length is missing"))
  }

  const n = Number.parseInt(l, 10)

  if (Number.isNaN(n)) {
    return r.error(new Error(`Content-Length ${l} is invalid`))
  }

  const b = await r.safeAsync(res.text.bind(res))
  if (b.err) {
    return r.error(new Error("Reading text", {cause: b.err}))
  }

  const e = new TextEncoder()

  const x = e.encode(b.v)

  if (x.length !== n) {
    return r.error(new Error("Content-Length mismatch"))
  }

  const j = r.safeSync(JSON.parse, b.v)
  if (j.err) {
    return r.error(new Error("Parsing JSON", {cause: j.err}))
  }

  return r.ok(j.v)
}

export async function readFetchText(res: Response): Promise<r.Result<string, Error>> {
  const t = res.headers.get("Content-Type")

  if (!t) {
    return r.error(new Error("Content-Type is missing"))
  }

  if (t !== "text/plain; charset=utf-8") {
    return r.error(new Error(`Content-Type ${t} is not 'text/plain; charset=utf-8'`))
  }

  const l = res.headers.get("Content-Length")

  if (!l) {
    return r.error(new Error("Content-Length is missing"))
  }

  const n = Number.parseInt(l, 10)

  if (Number.isNaN(n)) {
    return r.error(new Error(`Content-Length ${l} is invalid`))
  }

  const b = await r.safeAsync(res.text.bind(res))
  if (b.err) {
    return r.error(new Error("Reading text", {cause: b.err}))
  }

  const e = new TextEncoder()

  const x = e.encode(b.v)

  if (x.length !== n) {
    return r.error(new Error("Content-Length mismatch"))
  }

  return r.ok(b.v)
}

export async function readHttpData(req: http.IncomingMessage): Promise<r.Result<Uint8Array[], Error>> {
  if (!req.readable) {
    return r.error(new Error("Request is not readable"))
  }

  const e = (res: (v: r.Result<Uint8Array[], Error>) => void): void => {
    const b: Uint8Array[] = []

    const onError = (err: Error): void => {
      close(r.error(new Error("Request error", {cause: err})))
    }

    const onClose = (): void => {
      close(r.error(new Error("Request closed")))
    }

    const onData = (c: Uint8Array): void => {
      b.push(c)
    }

    const onEnd = (): void => {
      if (req.complete) {
        close(r.ok(b))
      } else {
        close(r.error(new Error("Request is not complete")))
      }
    }

    const close = (r: r.Result<Uint8Array[], Error>): void => {
      req.removeListener("error", onError)
      req.removeListener("close", onClose)
      req.removeListener("data", onData)
      req.removeListener("end", onEnd)
      res(r)
    }

    req.addListener("error", onError)
    req.addListener("close", onClose)
    req.addListener("data", onData)
    req.addListener("end", onEnd)
  }

  const w = await new Promise(e)
  if (w.err) {
    return r.error(new Error("Reading request", {cause: w.err}))
  }

  return r.ok(w.v)
}

export async function readHttpForm(req: http.IncomingMessage): Promise<r.Result<Record<string, string | string[] | undefined>, Error>> {
  const t = req.headers["content-type"]

  if (!t) {
    return r.error(new Error("Content-Type is missing"))
  }

  if (t !== "application/x-www-form-urlencoded") {
    return r.error(new Error(`Content-Type ${t} is not 'application/x-www-form-urlencoded'`))
  }

  const l = req.headers["content-length"]

  if (!l) {
    return r.error(new Error("Content-Length is missing"))
  }

  const n = Number.parseInt(l, 10)

  if (Number.isNaN(n)) {
    return r.error(new Error(`Content-Length ${l} is invalid`))
  }

  const d = await readHttpData(req)
  if (d.err) {
    return r.error(new Error("Reading data", {cause: d.err}))
  }

  const b = r.safeSync(Buffer.concat.bind(Buffer), d.v)
  if (b.err) {
    return r.error(new Error("Concatenating data", {cause: b.err}))
  }

  const s = r.safeSync(b.v.toString.bind(b.v), "utf8")
  if (s.err) {
    return r.error(new Error("Converting data", {cause: s.err}))
  }

  const e = new TextEncoder()

  const x = e.encode(s.v)

  if (x.length !== n) {
    return r.error(new Error("Content-Length mismatch"))
  }

  const q = r.safeSync(querystring.parse, s.v)
  if (q.err) {
    return r.error(new Error("Parsing data", {cause: q.err}))
  }

  return r.ok({...q.v})
}

export async function readHttpJson(req: http.IncomingMessage): Promise<r.Result<unknown, Error>> {
  const t = req.headers["content-type"]

  if (!t) {
    return r.error(new Error("Content-Type is missing"))
  }

  if (t !== "application/json; charset=utf-8") {
    return r.error(new Error(`Content-Type ${t} is not 'application/json; charset=utf-8'`))
  }

  const l = req.headers["content-length"]

  if (!l) {
    return r.error(new Error("Content-Length is missing"))
  }

  const n = Number.parseInt(l, 10)

  if (Number.isNaN(n)) {
    return r.error(new Error(`Content-Length ${l} is invalid`))
  }

  const d = await readHttpData(req)
  if (d.err) {
    return r.error(new Error("Reading data", {cause: d.err}))
  }

  const b = r.safeSync(Buffer.concat.bind(Buffer), d.v)
  if (b.err) {
    return r.error(new Error("Concatenating data", {cause: b.err}))
  }

  const s = r.safeSync(b.v.toString.bind(b.v), "utf8")
  if (s.err) {
    return r.error(new Error("Converting data", {cause: s.err}))
  }

  const e = new TextEncoder()

  const x = e.encode(s.v)

  if (x.length !== n) {
    return r.error(new Error("Content-Length mismatch"))
  }

  const j = r.safeSync(JSON.parse, s.v)
  if (j.err) {
    return r.error(new Error("Parsing data", {cause: j.err}))
  }

  return r.ok(j.v)
}

export async function sendJson(res: http.ServerResponse, statusCode: number, body: unknown): Promise<r.Result<void, Error>> {
  if (!res.writable) {
    return r.error(new Error("Response is not writable"))
  }

  const s = r.safeSync(JSON.stringify, body, null, 2)
  if (s.err) {
    return r.error(new Error("Stringifying body", {cause: s.err}))
  }

  if (!res.getHeader("Content-Type")) {
    res.setHeader("Content-Type", "application/json")
  }

  const h = r.safeSync(res.writeHead.bind(res), statusCode)
  if (h.err) {
    return r.error(new Error("Writing head", {cause: h.err}))
  }

  const e = (resolve: (v: r.Result<void, Error>) => void): void => {
    const onError = (err: Error): void => {
      close(new Error("Response error", {cause: err}))
    }

    const close = (err?: Error): void => {
      if (err) {
        resolve(r.error(err))
      } else {
        resolve(r.ok())
      }
    }

    res.once("error", onError)
    res.end(s.v, close)
  }

  const w = await new Promise(e)
  if (w.err) {
    return r.error(new Error("Sending response", {cause: w.err}))
  }

  return r.ok(w.v)
}

export type SetupBinOptions = {
  host: string
  port: number
  env: Record<string, string>
}

export async function setupBin(t: test.TestContext, o: SetupBinOptions): Promise<void> {
  const so: childProcess.SpawnOptions = {
    env: {
      ...process.env,
      ...o.env,
    },
  }

  const cp = childProcess.spawn(
    "node",
    ["./bin/onlyoffice-docspace-mcp.js"],
    so,
  )

  const onAfter: test.TestContextHookFn = () => {
    cp.kill()
  }

  t.after(onAfter)

  const wp = await waitForPort(o.port, o.host)
  assert.ok(wp.err === undefined)
}

export async function setupHttp(t: test.TestContext): Promise<[http.Server, net.AddressInfo]> {
  const s = new http.Server()

  const onAfter: test.TestContextHookFn = async() => {
    const e = (res: (v: r.Result<void, Error>) => void): void => {
      const onClose = (err: Error | undefined): void => {
        if (err) {
          res(r.error(err))
        } else {
          res(r.ok())
        }
      }

      s.close(onClose)
    }

    const w = await new Promise(e)
    assert.ok(w.err === undefined)
  }

  t.after(onAfter)

  const e = (res: (v: r.Result<void, Error>) => void): void => {
    const onError = (err: Error): void => {
      res(r.error(err))
    }

    const onListening = (): void => {
      res(r.ok())
    }

    s.once("error", onError)
    s.once("listening", onListening)
  }

  const p = new Promise(e)

  const listen: (port: number, host: string) => net.Server = s.listen.bind(s)

  const l = r.safeSync(listen, 0, "::")
  assert.ok(l.err === undefined)

  const w = await p
  assert.ok(w.err === undefined)

  const a = s.address()
  assert.ok(a && typeof a === "object")

  return [s, a]
}

export type SetupMcpOptions = {
  transport: "stdio" | "sse" | "streamable-http"
  host: string
  port: number
  env: Record<string, string>
}

export async function setupMcp(t: test.TestContext, o: SetupMcpOptions): Promise<client.Client> {
  const co: types.Implementation = {
    name: "test",
    version: "0.0.0",
  }

  const cl = new client.Client(co)

  let onAfter: test.TestContextHookFn = async() => {
    await cl.close()
  }

  t.after(onAfter)

  let tr: transport.Transport | undefined

  if (o.transport === "stdio") {
    const to: stdio.StdioServerParameters = {
      command: "node",
      args: ["./bin/onlyoffice-docspace-mcp.js"],
      env: o.env,
    }

    tr = new stdio.StdioClientTransport(to)
  } else {
    const so: childProcess.SpawnOptions = {
      env: {
        ...process.env,
        ...o.env,
      },
      shell: true,
    }

    const cp = childProcess.spawn(
      "node",
      ["./bin/onlyoffice-docspace-mcp.js"],
      so,
    )

    onAfter = () => {
      cp.kill()
    }

    t.after(onAfter)

    const w = await waitForPort(o.port, o.host)
    assert.ok(w.err === undefined)

    const b = `http://[${o.host}]:${o.port}/`

    let e: string | undefined

    if (o.transport === "sse") {
      e = "sse"
    } else {
      e = "mcp"
    }

    const u = r.safeNew(URL, e, b)
    assert.ok(u.err === undefined)

    if (o.transport === "sse") {
      tr = new sse.SSEClientTransport(u.v)
    } else {
      tr = new streamableHttp.StreamableHTTPClientTransport(u.v)
    }
  }

  const cr = await r.safeAsync(cl.connect.bind(cl), tr)
  assert.ok(cr.err === undefined)

  return cl
}

export async function waitForPort(p: number, h: string): Promise<r.Result<void, Error>> {
  const timeout = 30000
  const interval = 100

  const now = Date.now()

  while (Date.now() - now < timeout) {
    const pe = (res: (v: unknown) => void): void => {
      setTimeout(res, interval)
    }

    await new Promise(pe)

    const fe = (res: (v: boolean) => void): void => {
      const s = new net.Socket()

      const onError = (): void => {
        s.destroy()
        res(false)
      }

      const onConnect = (): void => {
        s.destroy()
        res(true)
      }

      s.once("error", onError)
      s.once("connect", onConnect)

      s.connect(p, h)
    }

    const f = await new Promise(fe)
    if (f) {
      return r.ok()
    }
  }

  return r.error(new Error(`Timeout waiting for port ${p}`))
}
