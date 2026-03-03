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

export function inDelta(a: number, e: number, d: number): boolean {
	return Math.abs(e - a) <= d
}

export async function onRequest(t: test.TestContext, s: http.Server, l: AsyncRequestListener): Promise<void> {
	let e = (_: unknown, reject: (err: Error) => void): void => {
		let onRequest: http.RequestListener = (req, res) => {
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

		let onAfter: test.TestContextHookFn = () => {
			s.removeListener("request", onRequest)
		}

		t.after(onAfter)

		s.addListener("request", onRequest)
	}

	await new Promise(e)
}

export function parseFetchLocation(res: Response): r.Result<URL, Error> {
	let s = res.headers.get("Location")
	if (!s) {
		return r.error(new Error("Location is missing"))
	}

	let u = r.safeNew(URL, s)
	if (u.err) {
		return r.error(new Error("Parsing URL", {cause: u.err}))
	}

	return r.ok(u.v)
}

export function powerSet<T>(arr: T[]): T[][] {
	let x: T[][] = []

	for (let i = 0; i < Math.pow(2, arr.length); i += 1) {
		let y: T[] = []

		for (let [j, e] of arr.entries()) {
			if (i >> j & 1) {
				y.push(e)
			}
		}

		x.push(y)
	}

	return x
}

export async function randomAddress(): Promise<r.Result<net.AddressInfo, Error>> {
	let s = new net.Server()

	let e = (res: (v: r.Result<void, Error>) => void): void => {
		let onError = (err: Error): void => {
			res(r.error(err))
		}

		let onListening = (): void => {
			res(r.ok())
		}

		s.once("error", onError)
		s.once("listening", onListening)
	}

	let p = new Promise(e)

	let listen: (port: number, host: string) => net.Server = s.listen.bind(s)

	let l = r.safeSync(listen, 0, "::")
	if (l.err) {
		return r.error(new Error("Listening server", {cause: l.err}))
	}

	let w = await p
	if (w.err) {
		return r.error(new Error("Waiting for server", {cause: w.err}))
	}

	let a = s.address()

	if (!a || typeof a !== "object") {
		return r.error(new Error("Address is not object"))
	}

	e = (res) => {
		let onClose = (err: Error | undefined): void => {
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
	let t = res.headers.get("Content-Type")

	if (!t) {
		return r.error(new Error("Content-Type is missing"))
	}

	if (t !== "application/json; charset=utf-8") {
		return r.error(new Error(`Content-Type ${t} is not 'application/json; charset=utf-8'`))
	}

	let l = res.headers.get("Content-Length")

	if (!l) {
		return r.error(new Error("Content-Length is missing"))
	}

	let n = Number.parseInt(l, 10)

	if (Number.isNaN(n)) {
		return r.error(new Error(`Content-Length ${l} is invalid`))
	}

	let b = await r.safeAsync(res.text.bind(res))
	if (b.err) {
		return r.error(new Error("Reading text", {cause: b.err}))
	}

	let e = new TextEncoder()

	let x = e.encode(b.v)

	if (x.length !== n) {
		return r.error(new Error("Content-Length mismatch"))
	}

	let j = r.safeSync(JSON.parse, b.v)
	if (j.err) {
		return r.error(new Error("Parsing JSON", {cause: j.err}))
	}

	return r.ok(j.v)
}

export async function readFetchText(res: Response): Promise<r.Result<string, Error>> {
	let t = res.headers.get("Content-Type")

	if (!t) {
		return r.error(new Error("Content-Type is missing"))
	}

	if (t !== "text/plain; charset=utf-8") {
		return r.error(new Error(`Content-Type ${t} is not 'text/plain; charset=utf-8'`))
	}

	let l = res.headers.get("Content-Length")

	if (!l) {
		return r.error(new Error("Content-Length is missing"))
	}

	let n = Number.parseInt(l, 10)

	if (Number.isNaN(n)) {
		return r.error(new Error(`Content-Length ${l} is invalid`))
	}

	let b = await r.safeAsync(res.text.bind(res))
	if (b.err) {
		return r.error(new Error("Reading text", {cause: b.err}))
	}

	let e = new TextEncoder()

	let x = e.encode(b.v)

	if (x.length !== n) {
		return r.error(new Error("Content-Length mismatch"))
	}

	return r.ok(b.v)
}

export async function readHttpData(req: http.IncomingMessage): Promise<r.Result<Uint8Array[], Error>> {
	if (!req.readable) {
		return r.error(new Error("Request is not readable"))
	}

	let e = (res: (v: r.Result<Uint8Array[], Error>) => void): void => {
		let b: Uint8Array[] = []

		let onError = (err: Error): void => {
			close(r.error(new Error("Request error", {cause: err})))
		}

		let onClose = (): void => {
			close(r.error(new Error("Request closed")))
		}

		let onData = (c: Uint8Array): void => {
			b.push(c)
		}

		let onEnd = (): void => {
			if (req.complete) {
				close(r.ok(b))
			} else {
				close(r.error(new Error("Request is not complete")))
			}
		}

		let close = (r: r.Result<Uint8Array[], Error>): void => {
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

	let w = await new Promise(e)
	if (w.err) {
		return r.error(new Error("Reading request", {cause: w.err}))
	}

	return r.ok(w.v)
}

export async function readHttpForm(req: http.IncomingMessage): Promise<r.Result<Record<string, string | string[] | undefined>, Error>> {
	let t = req.headers["content-type"]

	if (!t) {
		return r.error(new Error("Content-Type is missing"))
	}

	if (t !== "application/x-www-form-urlencoded") {
		return r.error(new Error(`Content-Type ${t} is not 'application/x-www-form-urlencoded'`))
	}

	let l = req.headers["content-length"]

	if (!l) {
		return r.error(new Error("Content-Length is missing"))
	}

	let n = Number.parseInt(l, 10)

	if (Number.isNaN(n)) {
		return r.error(new Error(`Content-Length ${l} is invalid`))
	}

	let d = await readHttpData(req)
	if (d.err) {
		return r.error(new Error("Reading data", {cause: d.err}))
	}

	let b = r.safeSync(Buffer.concat.bind(Buffer), d.v)
	if (b.err) {
		return r.error(new Error("Concatenating data", {cause: b.err}))
	}

	let s = r.safeSync(b.v.toString.bind(b.v), "utf8")
	if (s.err) {
		return r.error(new Error("Converting data", {cause: s.err}))
	}

	let e = new TextEncoder()

	let x = e.encode(s.v)

	if (x.length !== n) {
		return r.error(new Error("Content-Length mismatch"))
	}

	let q = r.safeSync(querystring.parse, s.v)
	if (q.err) {
		return r.error(new Error("Parsing data", {cause: q.err}))
	}

	return r.ok({...q.v})
}

export async function readHttpJson(req: http.IncomingMessage): Promise<r.Result<unknown, Error>> {
	let t = req.headers["content-type"]

	if (!t) {
		return r.error(new Error("Content-Type is missing"))
	}

	if (t !== "application/json; charset=utf-8") {
		return r.error(new Error(`Content-Type ${t} is not 'application/json; charset=utf-8'`))
	}

	let l = req.headers["content-length"]

	if (!l) {
		return r.error(new Error("Content-Length is missing"))
	}

	let n = Number.parseInt(l, 10)

	if (Number.isNaN(n)) {
		return r.error(new Error(`Content-Length ${l} is invalid`))
	}

	let d = await readHttpData(req)
	if (d.err) {
		return r.error(new Error("Reading data", {cause: d.err}))
	}

	let b = r.safeSync(Buffer.concat.bind(Buffer), d.v)
	if (b.err) {
		return r.error(new Error("Concatenating data", {cause: b.err}))
	}

	let s = r.safeSync(b.v.toString.bind(b.v), "utf8")
	if (s.err) {
		return r.error(new Error("Converting data", {cause: s.err}))
	}

	let e = new TextEncoder()

	let x = e.encode(s.v)

	if (x.length !== n) {
		return r.error(new Error("Content-Length mismatch"))
	}

	let j = r.safeSync(JSON.parse, s.v)
	if (j.err) {
		return r.error(new Error("Parsing data", {cause: j.err}))
	}

	return r.ok(j.v)
}

export async function sendJson(res: http.ServerResponse, statusCode: number, body: unknown): Promise<r.Result<void, Error>> {
	if (!res.writable) {
		return r.error(new Error("Response is not writable"))
	}

	let s = r.safeSync(JSON.stringify, body, null, 2)
	if (s.err) {
		return r.error(new Error("Stringifying body", {cause: s.err}))
	}

	if (!res.getHeader("Content-Type")) {
		res.setHeader("Content-Type", "application/json")
	}

	let h = r.safeSync(res.writeHead.bind(res), statusCode)
	if (h.err) {
		return r.error(new Error("Writing head", {cause: h.err}))
	}

	let e = (resolve: (v: r.Result<void, Error>) => void): void => {
		let onError = (err: Error): void => {
			close(new Error("Response error", {cause: err}))
		}

		let close = (err?: Error): void => {
			if (err) {
				resolve(r.error(err))
			} else {
				resolve(r.ok())
			}
		}

		res.once("error", onError)
		res.end(s.v, close)
	}

	let w = await new Promise(e)
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
	let so: childProcess.SpawnOptions = {
		env: {
			...process.env,
			...o.env,
		},
	}

	let cp = childProcess.spawn(
		"node",
		["./bin/onlyoffice-docspace-mcp.js"],
		so,
	)

	let onAfter: test.TestContextHookFn = () => {
		cp.kill()
	}

	t.after(onAfter)

	let wp = await waitForPort(o.port, o.host)
	assert.ok(wp.err === undefined)
}

export async function setupHttp(t: test.TestContext): Promise<[http.Server, net.AddressInfo]> {
	let s = new http.Server()

	let onAfter: test.TestContextHookFn = async() => {
		let e = (res: (v: r.Result<void, Error>) => void): void => {
			let onClose = (err: Error | undefined): void => {
				if (err) {
					res(r.error(err))
				} else {
					res(r.ok())
				}
			}

			s.close(onClose)
		}

		let w = await new Promise(e)
		assert.ok(w.err === undefined)
	}

	t.after(onAfter)

	let e = (res: (v: r.Result<void, Error>) => void): void => {
		let onError = (err: Error): void => {
			res(r.error(err))
		}

		let onListening = (): void => {
			res(r.ok())
		}

		s.once("error", onError)
		s.once("listening", onListening)
	}

	let p = new Promise(e)

	let listen: (port: number, host: string) => net.Server = s.listen.bind(s)

	let l = r.safeSync(listen, 0, "::")
	assert.ok(l.err === undefined)

	let w = await p
	assert.ok(w.err === undefined)

	let a = s.address()
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
	let co: types.Implementation = {
		name: "test",
		version: "0.0.0",
	}

	let cl = new client.Client(co)

	let onAfter: test.TestContextHookFn = async() => {
		await cl.close()
	}

	t.after(onAfter)

	let tr: transport.Transport | undefined

	if (o.transport === "stdio") {
		let to: stdio.StdioServerParameters = {
			command: "node",
			args: ["./bin/onlyoffice-docspace-mcp.js"],
			env: o.env,
		}

		tr = new stdio.StdioClientTransport(to)
	} else {
		let so: childProcess.SpawnOptions = {
			env: {
				...process.env,
				...o.env,
			},
			shell: true,
		}

		let cp = childProcess.spawn(
			"node",
			["./bin/onlyoffice-docspace-mcp.js"],
			so,
		)

		onAfter = () => {
			cp.kill()
		}

		t.after(onAfter)

		let w = await waitForPort(o.port, o.host)
		assert.ok(w.err === undefined)

		let b = `http://[${o.host}]:${o.port}/`

		let e: string | undefined

		if (o.transport === "sse") {
			e = "sse"
		} else {
			e = "mcp"
		}

		let u = r.safeNew(URL, e, b)
		assert.ok(u.err === undefined)

		if (o.transport === "sse") {
			tr = new sse.SSEClientTransport(u.v)
		} else {
			tr = new streamableHttp.StreamableHTTPClientTransport(u.v)
		}
	}

	let cr = await r.safeAsync(cl.connect.bind(cl), tr)
	assert.ok(cr.err === undefined)

	return cl
}

export async function waitForPort(p: number, h: string): Promise<r.Result<void, Error>> {
	let timeout = 30000
	let interval = 100

	let now = Date.now()

	while (Date.now() - now < timeout) {
		let pe = (res: (v: unknown) => void): void => {
			setTimeout(res, interval)
		}

		await new Promise(pe)

		let fe = (res: (v: boolean) => void): void => {
			let s = new net.Socket()

			let onError = (): void => {
				s.destroy()
				res(false)
			}

			let onConnect = (): void => {
				s.destroy()
				res(true)
			}

			s.once("error", onError)
			s.once("connect", onConnect)

			s.connect(p, h)
		}

		let f = await new Promise(fe)
		if (f) {
			return r.ok()
		}
	}

	return r.error(new Error(`Timeout waiting for port ${p}`))
}
