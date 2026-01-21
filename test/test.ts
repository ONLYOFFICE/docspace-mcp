/**
 * (c) Copyright Ascensio System SIA 2025
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @license
 */

/* eslint-disable typescript/consistent-type-definitions */

import assert from "node:assert/strict"
import childProcess from "node:child_process"
import http from "node:http"
import net from "node:net"
import querystring from "node:querystring"
import test from "node:test"
import * as client from "@modelcontextprotocol/sdk/client/index.js"
import * as sse from "@modelcontextprotocol/sdk/client/sse.js"
import * as stdio from "@modelcontextprotocol/sdk/client/stdio.js"
import * as streamableHttp from "@modelcontextprotocol/sdk/client/streamableHttp.js"
import type * as transport from "@modelcontextprotocol/sdk/shared/transport.js"
import * as types from "@modelcontextprotocol/sdk/types.js"
import jwt from "jsonwebtoken"
import type * as z from "zod"
import * as meta from "../lib/meta.ts"
import * as r from "../lib/util/result.ts"

function powerSet<T>(arr: T[]): T[][] {
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

function inDelta(a: number, e: number, d: number): boolean {
	return Math.abs(e - a) <= d
}

async function randomAddress(): Promise<r.Result<net.AddressInfo, Error>> {
	let s = new net.Server()

	let p = new Promise<r.Result<void, Error>>((res) => {
		s.once("error", (err) => {
			res(r.error(err))
		})

		s.once("listening", () => {
			res(r.ok())
		})
	})

	let listen: (port: number, host: string) => void = s.listen.bind(s)

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

	p = new Promise<r.Result<void, Error>>((res) => {
		s.close((err) => {
			if (err) {
				res(r.error(err))
			} else {
				res(r.ok())
			}
		})
	})

	w = await p
	if (w.err) {
		return r.error(new Error("Closing server", {cause: w.err}))
	}

	return r.ok(a)
}

async function waitForPort(p: number, h: string): Promise<r.Result<void, Error>> {
	let t = 30000
	let i = 100

	let s = Date.now()

	while (Date.now() - s < t) {
		await new Promise((res) => {
			setTimeout(res, i)
		})

		let f = await new Promise<boolean>((res) => {
			let s = new net.Socket()

			s.once("error", () => {
				s.destroy()
				res(false)
			})

			s.once("connect", () => {
				s.destroy()
				res(true)
			})

			s.connect(p, h)
		})

		if (f) {
			return r.ok()
		}
	}

	return r.error(new Error(`Timeout waiting for port ${p}`))
}

async function readFetchJson(res: Response): Promise<r.Result<unknown, Error>> {
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

async function readFetchText(res: Response): Promise<r.Result<string, Error>> {
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

function parseFetchLocation(res: Response): r.Result<URL, Error> {
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

async function readHttpForm(req: http.IncomingMessage): Promise<r.Result<Record<string, string | string[] | undefined>, Error>> {
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

async function readHttpData(req: http.IncomingMessage): Promise<r.Result<Uint8Array[], Error>> {
	if (!req.readable) {
		return r.error(new Error("Request is not readable"))
	}

	return await new Promise<r.Result<Uint8Array[], Error>>((resolve) => {
		let a: Uint8Array[] = []

		let onError = (err: Error): void => {
			close(r.error(new Error("Request error", {cause: err})))
		}

		let onClose = (): void => {
			close(r.error(new Error("Request closed")))
		}

		let onData = (c: Uint8Array): void => {
			a.push(c)
		}

		let onEnd = (): void => {
			if (req.complete) {
				close(r.ok(a))
			} else {
				close(r.error(new Error("Request is not complete")))
			}
		}

		let close = (r: r.Result<Uint8Array[], Error>): void => {
			req.removeListener("error", onError)
			req.removeListener("close", onClose)
			req.removeListener("data", onData)
			req.removeListener("end", onEnd)
			resolve(r)
		}

		req.on("error", onError)
		req.on("close", onClose)
		req.on("data", onData)
		req.on("end", onEnd)
	})
}

async function sendJson(res: http.ServerResponse, statusCode: number, body: unknown): Promise<r.Result<void, Error>> {
	if (!res.writable) {
		return r.error(new Error("Response is not writable"))
	}

	let sr = r.safeSync(JSON.stringify, body, null, 2)
	if (sr.err) {
		return r.error(new Error("Stringifying body", {cause: sr.err}))
	}

	if (!res.getHeader("Content-Type")) {
		res.setHeader("Content-Type", "application/json")
	}

	let hr = r.safeSync(res.writeHead.bind(res), statusCode)
	if (hr.err) {
		return r.error(new Error("Writing head", {cause: hr.err}))
	}

	return await new Promise((resolve) => {
		let onError = (err: Error): void => {
			end(new Error("Response error", {cause: err}))
		}

		let end = (err?: Error): void => {
			res.removeListener("error", onError)

			if (err) {
				resolve(r.error(err))
			} else {
				resolve(r.ok())
			}
		}

		res.on("error", onError)
		res.end(sr.v, end)
	})
}

type AsyncRequestListener = (...args: Parameters<http.RequestListener>) => PromiseLike<void> | void

async function onRequest(t: test.TestContext, s: http.Server, l: AsyncRequestListener): Promise<void> {
	await new Promise<void>((_, reject) => {
		let w: http.RequestListener = (req, res) => {
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

		t.after(() => {
			s.removeListener("request", w)
		})

		s.on("request", w)
	})
}

async function setupHttp(t: test.TestContext): Promise<[http.Server, net.AddressInfo]> {
	let s = new http.Server()

	t.after(async() => {
		let p = new Promise<r.Result<void, Error>>((res) => {
			s.close((err) => {
				if (err) {
					res(r.error(err))
				} else {
					res(r.ok())
				}
			})
		})

		let w = await p
		assert.ok(w.err === undefined)
	})

	let p = new Promise<r.Result<void, Error>>((res) => {
		s.once("error", (err) => {
			res(r.error(err))
		})

		s.once("listening", () => {
			res(r.ok())
		})
	})

	let listen: (port: number, host: string) => void = s.listen.bind(s)

	let l = r.safeSync(listen, 0, "::")
	assert.ok(l.err === undefined)

	let w = await p
	assert.ok(w.err === undefined)

	let a = s.address()
	assert.ok(a && typeof a === "object")

	return [s, a]
}

type SetupBinOptions = {
	host: string
	port: number
	env: Record<string, string>
}

async function setupBin(t: test.TestContext, o: SetupBinOptions): Promise<void> {
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

	t.after(() => {
		cp.kill()
	})

	let wp = await waitForPort(o.port, o.host)
	assert.ok(wp.err === undefined)
}

type SetupMcpOptions = {
	transport: "stdio" | "sse" | "streamable-http"
	host: string
	port: number
	env: Record<string, string>
}

async function setupMcp(t: test.TestContext, o: SetupMcpOptions): Promise<client.Client> {
	let co: types.Implementation = {
		name: "test",
		version: "0.0.0",
	}

	let cl = new client.Client(co)

	t.after(async() => {
		await cl.close()
	})

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

		t.after(() => {
			cp.kill()
		})

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

void test.suite("validates config", () => {
	type Suite = {
		name: string
		tests: Record<string, string>[]
		text: string
	}

	let suits: Suite[] = [
		{
			name: "no tools left",
			tests: [
				{
					DOCSPACE_TOOLSETS: "",
					DOCSPACE_BASE_URL: "http://localhost/",
					DOCSPACE_API_KEY: "xxx",
				},
				{
					DOCSPACE_TOOLSETS: "people",
					DOCSPACE_ENABLED_TOOLS: "download_file_as_text",
					DOCSPACE_DISABLED_TOOLS: "download_file_as_text,get_all_people",
					DOCSPACE_BASE_URL: "http://localhost/",
					DOCSPACE_API_KEY: "xxx",
				},
			],
			text: "No tools left",
		},
		{
			name: "no password",
			tests: [
				{
					DOCSPACE_BASE_URL: "http://localhost/",
					DOCSPACE_USERNAME: "xxx",
				},
			],
			text: "No password",
		},
		{
			name: "no username",
			tests: [
				{
					DOCSPACE_BASE_URL: "http://localhost/",
					DOCSPACE_PASSWORD: "xxx",
				},
			],
			text: "No username",
		},
		{
			name: "no api base url",
			tests: [],
			text: "No API base URL",
		},
		{
			name: "no oauth client secret",
			tests: [],
			text: "No OAuth client secret",
		},
		{
			name: "no oauth client id",
			tests: [],
			text: "No OAuth client ID",
		},
		{
			name: "no auth method",
			tests: [],
			text: "No authentication method",
		},
		{
			name: "multiple auth methods",
			tests: [],
			text: "Multiple authentication methods",
		},
		{
			name: "no server base url",
			tests: [],
			text: "No server base URL",
		},
		{
			name: "no server host",
			tests: [],
			text: "No server host",
		},
	]

	for (let i = 0; i < 4; i += 1) {
		let t: Record<string, string> = {}

		switch (i) {
		case 0:
			t.DOCSPACE_AUTHORIZATION = "xxx"
			break
		case 1:
			t.DOCSPACE_API_KEY = "xxx"
			break
		case 2:
			t.DOCSPACE_AUTH_TOKEN = "xxx"
			break
		case 3:
			t.DOCSPACE_USERNAME = "xxx"
			t.DOCSPACE_PASSWORD = "xxx"
			break
		}

		suits[3].tests.push(t)
	}

	for (let tr of ["stdio", "sse", "streamable-http", "http"]) {
		if (tr !== "stdio") {
			suits[4].tests.push(
				{
					DOCSPACE_TRANSPORT: tr,
					DOCSPACE_OAUTH_BASE_URL: "http://localhost/",
					DOCSPACE_OAUTH_CLIENT_ID: "xxx",
					DOCSPACE_SERVER_BASE_URL: "http://localhost/",
				},
			)

			suits[5].tests.push(
				{
					DOCSPACE_TRANSPORT: tr,
					DOCSPACE_OAUTH_BASE_URL: "http://localhost/",
					DOCSPACE_OAUTH_CLIENT_SECRET: "xxx",
					DOCSPACE_SERVER_BASE_URL: "http://localhost/",
				},
			)
		}

		if (tr === "stdio") {
			suits[6].tests.push(
				{
					DOCSPACE_TRANSPORT: tr,
				},
			)
		} else {
			suits[6].tests.push(
				{
					DOCSPACE_TRANSPORT: tr,
					DOCSPACE_REQUEST_QUERY: "0",
					DOCSPACE_REQUEST_HEADER_PREFIX: "",
				},
				{
					DOCSPACE_TRANSPORT: tr,
					DOCSPACE_REQUEST_AUTHORIZATION_HEADER: "0",
					DOCSPACE_REQUEST_HEADER_PREFIX: "",
				},
			)
		}

		if (tr === "stdio") {
			for (let g of powerSet([0, 1, 2, 3, 4])) {
				if (
					// The case when no auth.
					g.length === 0 ||
					// The case when auth is set correctly.
					g.length === 1 ||
					// The case when auth is username+password.
					g.length === 2 &&
					g[0] === 3 &&
					g[1] === 4
				) {
					continue
				}

				let t: Record<string, string> = {
					DOCSPACE_TRANSPORT: tr,
					DOCSPACE_BASE_URL: "http://localhost/",
				}

				for (let i of g) {
					switch (i) {
					case 0:
						t.DOCSPACE_AUTHORIZATION = "xxx"
						break
					case 1:
						t.DOCSPACE_API_KEY = "xxx"
						break
					case 2:
						t.DOCSPACE_AUTH_TOKEN = "xxx"
						break
					case 3:
						t.DOCSPACE_USERNAME = "xxx"
						t.DOCSPACE_PASSWORD = "xxx"
						break
					case 4:
						t.DOCSPACE_USERNAME = "xxx"
						t.DOCSPACE_PASSWORD = "xxx"
						break
					}
				}

				suits[7].tests.push(t)
			}
		} else {
			for (let g of powerSet([0, 1, 2, 3, 4, 5])) {
				if (
					// The case when no auth.
					g.length === 0 ||
					// The case when auth is set correctly.
					g.length === 1 ||
					// The case when auth is username+password.
					g.length === 2 &&
					g[0] === 3 &&
					g[1] === 4
				) {
					continue
				}

				let t: Record<string, string> = {
					DOCSPACE_TRANSPORT: tr,
				}

				for (let i of g) {
					switch (i) {
					case 0:
						t.DOCSPACE_BASE_URL = "http://localhost/"
						t.DOCSPACE_AUTHORIZATION = "xxx"
						break
					case 1:
						t.DOCSPACE_BASE_URL = "http://localhost/"
						t.DOCSPACE_API_KEY = "xxx"
						break
					case 2:
						t.DOCSPACE_BASE_URL = "http://localhost/"
						t.DOCSPACE_AUTH_TOKEN = "xxx"
						break
					case 3:
						t.DOCSPACE_BASE_URL = "http://localhost/"
						t.DOCSPACE_USERNAME = "xxx"
						t.DOCSPACE_PASSWORD = "xxx"
						break
					case 4:
						t.DOCSPACE_BASE_URL = "http://localhost/"
						t.DOCSPACE_USERNAME = "xxx"
						t.DOCSPACE_PASSWORD = "xxx"
						break
					case 5:
						t.DOCSPACE_OAUTH_BASE_URL = "http://localhost/"
						t.DOCSPACE_SERVER_BASE_URL = "http://localhost/"
						break
					}
				}

				suits[7].tests.push(t)
			}
		}

		if (tr !== "stdio") {
			suits[8].tests.push(
				{
					DOCSPACE_TRANSPORT: tr,
					DOCSPACE_OAUTH_BASE_URL: "http://localhost/",
				},
			)

			suits[9].tests.push(
				{
					DOCSPACE_TRANSPORT: tr,
					DOCSPACE_HOST: "",
				},
			)
		}
	}

	for (let c of suits) {
		void test.suite(c.name, () => {
			for (let tt of c.tests) {
				let n = ""

				for (let [k, v] of Object.entries(tt)) {
					n += `${k}=${v} `
				}

				if (n.length !== 0) {
					n = n.slice(0, -1)
				}

				void test(n, async(t) => {
					let so: SetupMcpOptions = {
						transport: "stdio",
						host: "",
						port: 0,
						env: tt,
					}

					let cl = await setupMcp(t, so)

					let req: types.CallToolRequest = {
						method: "tools/call",
						params: {
							name: "non_existed",
						},
					}

					let a = await r.safeAsync(cl.request.bind(cl), req, types.CallToolResultSchema)
					assert.ok(a.err === undefined)

					let e: z.infer<typeof types.CallToolResultSchema> = {
						content: [
							{
								type: "text",
								text: c.text,
							},
						],
						isError: true,
					}

					assert.deepEqual(a.v, e)
				})
			}
		})
	}
})

void test("oauth server", (t) => {
	// todo: client.ts
	// upstream can respond without Content-Type
	// upstream can respond with invalid Content-Type
	// upstream can respond with invalid JSON

	// todo: errors
	// some error_descriptions have broken tabulation
	// some error_descriptions are not informative

	let setup = async(t: test.TestContext, e: object): Promise<net.AddressInfo> => {
		let a = await randomAddress()
		assert.ok(a.err === undefined)

		let o: SetupBinOptions = {
			host: a.v.address,
			port: a.v.port,
			env: {
				DOCSPACE_TRANSPORT: "http",
				DOCSPACE_HOST: a.v.address,
				DOCSPACE_PORT: `${a.v.port}`,
				DOCSPACE_OAUTH_BASE_URL: "http://localhost/",
				DOCSPACE_SERVER_BASE_URL: `http://[${a.v.address}]:${a.v.port}/`,
				DOCSPACE_REQUEST_QUERY: "0", // todo: questionable
				DOCSPACE_REQUEST_AUTHORIZATION_HEADER: "",
				DOCSPACE_REQUEST_HEADER_PREFIX: "",
				...e,
			},
		}

		await setupBin(t, o)

		return a.v
	}

	let withAuth = (fetch: typeof globalThis.fetch): typeof globalThis.fetch => {
		return async(input, init) => {
			if (!(input instanceof URL)) {
				throw new Error("Input is not URL")
			}

			if (!init) {
				throw new Error("Init is missing")
			}

			if (init.headers) {
				if (Array.isArray(init.headers) || init.headers instanceof Headers) {
					throw new Error("Headers are not object")
				}

				init.headers = {...init.headers}
			} else {
				init.headers = {}
			}

			let s = ""

			for (let c of "basic") {
				if (Math.random() < 0.5) {
					s += c.toLowerCase()
				} else {
					s += c.toUpperCase()
				}
			}

			let p = Buffer.from("xxx:yyy").toString("base64")

			init.headers.Authorization = `${s} ${p}`

			return await fetch(input, init)
		}
	}

	let sendAccessToken = async(
		_: Parameters<http.RequestListener>[0],
		res: Parameters<http.RequestListener>[1],
	): Promise<string> => {
		let o: jwt.SignOptions = {
			algorithm: "none",
		}

		let t = r.safeSync(jwt.sign, {}, "", o)
		assert.ok(t.err === undefined)

		let b: object = {
			access_token: t.v,
			token_type: "test",
		}

		let s = await sendJson(res, 200, b)
		assert.ok(s.err === undefined)

		return t.v
	}

	let requestAccessToken = async(a: net.AddressInfo): Promise<string> => {
		let u = r.safeNew(URL, "/oauth/token", `http://[${a.address}]:${a.port}/`)
		assert.ok(u.err === undefined)

		let f = new URLSearchParams()

		f.set("grant_type", "authorization_code")
		f.set("code", "vvv")

		let i: RequestInit = {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
			},
			body: f.toString(),
		}

		let fetch = withAuth(globalThis.fetch)

		let res = await r.safeAsync(fetch, u.v, i)
		assert.ok(res.err === undefined)

		assert.ok(res.v.status === 200)

		let b = await readFetchJson(res.v)
		assert.ok(b.err === undefined)

		assert.ok(b.v && typeof b.v === "object")
		assert.ok("access_token" in b.v && typeof b.v.access_token === "string")

		return b.v.access_token
	}

	let requestState = async(a: net.AddressInfo, q: URLSearchParams): Promise<string> => {
		let u = r.safeNew(URL, "/oauth/authorize", `http://[${a.address}]:${a.port}/`)
		assert.ok(u.err === undefined)

		let p = new URLSearchParams()

		p.set("response_type", "code")
		p.set("client_id", "xxx")
		p.set("redirect_uri", "http://localhost:8030")

		for (let [k, v] of q.entries()) {
			p.set(k, v)
		}

		u.v.search = p.toString()

		let i: RequestInit = {
			redirect: "manual",
		}

		let res = await r.safeAsync(fetch, u.v, i)
		assert.ok(res.err === undefined)

		assert.ok(res.v.status === 302)

		let l = parseFetchLocation(res.v)
		assert.ok(l.err === undefined)

		let s = l.v.searchParams.get("state")
		assert.ok(s)

		return s
	}

	let checkJwtAlg = (t: string, alg: jwt.Algorithm, k: string): void => {
		if (alg === "none") {
			let o: jwt.DecodeOptions = {
				complete: true,
			}

			let decode = jwt.decode as (t: string, o: jwt.DecodeOptions) => jwt.Jwt | null

			let j = decode(t, o)
			assert.ok(j)

			let h: object = {
				alg,
				typ: "JWT",
			}

			assert.deepEqual(j.header, h)

			assert.ok(j.signature.length === 0)
		} else {
			let o: jwt.VerifyOptions = {
				algorithms: [alg],
				complete: true,
				ignoreExpiration: true,
				ignoreNotBefore: true,
			}

			let verify = jwt.verify as (t: string, k: string, o: jwt.VerifyOptions) => jwt.Jwt

			let j = r.safeSync(verify, t, k, o)
			assert.ok(j.err === undefined)

			let h: object = {
				alg,
				typ: "JWT",
			}

			assert.deepEqual(j.v.header, h)

			assert.ok(j.v.signature.length !== 0)
		}
	}

	let checkJwtTtl = (t: string, ttl: number): void => {
		let o: jwt.DecodeOptions = {
			complete: true,
		}

		let decode = jwt.decode as (t: string, o: jwt.DecodeOptions) => jwt.Jwt | null

		let j = decode(t, o)
		assert.ok(j)

		assert.ok(typeof j.payload === "object")

		let now = Date.now()

		if (ttl) {
			assert.ok(j.payload.exp && inDelta(j.payload.exp * 1000, now + ttl, 3000))
		} else {
			assert.ok(!("exp" in j.payload))
		}

		assert.ok(j.payload.nbf && inDelta(j.payload.nbf * 1000, now, 3000))
		assert.ok(j.payload.iat && inDelta(j.payload.iat * 1000, now, 3000))
	}

	let checkJwtPayload = (t: string, p: object): void => {
		let o: jwt.DecodeOptions = {
			complete: true,
		}

		let decode = jwt.decode as (t: string, o: jwt.DecodeOptions) => jwt.Jwt | null

		let j = decode(t, o)
		assert.ok(j)

		assert.partialDeepStrictEqual(j.payload, p)
	}

	type TestCorsOptions = {
		env: object
		method: string
		path: string
	}

	let testCors = (t: test.TestContext, o: TestCorsOptions): void => {
		let check = (res: Response, ha: [string, string[]][]): void => {
			assert.ok(res.status === 204)

			for (let [k, v] of ha) {
				let h = res.headers.get(k)
				assert.ok(h)

				let a = h.split(",")

				for (let i = 0; i < a.length; i += 1) {
					a[i] = a[i].trim()
				}

				for (let e of v) {
					assert.ok(a.includes(e))
				}
			}
		}

		void t.test("cors", (t) => {
			let wh: [string, string[]][] = [
				["Access-Control-Allow-Origin", ["*"]],
				["Access-Control-Max-Age", ["86400"]],
				["Content-Length", ["0"]],
			]

			if (o.path.startsWith("/.well-known")) {
				wh.push(["Access-Control-Allow-Methods", ["GET"]])
				wh.push(["Vary", ["Access-Control-Request-Headers"]])
			} else if (o.path.startsWith("/oauth")) {
				wh.push(["Access-Control-Allow-Headers", ["Authorization", "Content-Type"]])
				wh.push(["Access-Control-Allow-Methods", ["GET", "POST"]])
				wh.push(["Access-Control-Expose-Headers", ["WWW-Authenticate"]])
			}

			void t.test("allows any origin by default", async(t) => {
				let a = await setup(t, o.env)

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let i: RequestInit = {
					method: "OPTIONS",
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				check(res.v, wh)
			})

			void t.test("allows any origin when explicitly set to wildcard", async(t) => {
				let e: object = {
					...o.env,
					DOCSPACE_SERVER_CORS_OAUTH_ORIGIN: "*",
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let i: RequestInit = {
					method: "OPTIONS",
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				check(res.v, wh)
			})

			void t.test("allows any origin when wildcard is in origin list", async(t) => {
				let e: object = {
					...o.env,
					DOCSPACE_SERVER_CORS_OAUTH_ORIGIN: "*,http://localhost",
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let i: RequestInit = {
					method: "OPTIONS",
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				check(res.v, wh)

				i = {
					method: "OPTIONS",
					headers: {
						Origin: "http://localhost",
					},
				}

				res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				check(res.v, wh)
			})

			let rh: [string, string[]][] = [
				["Access-Control-Max-Age", ["86400"]],
				["Content-Length", ["0"]],
			]

			if (o.path.startsWith("/.well-known")) {
				rh.push(["Access-Control-Allow-Methods", ["GET"]])
				rh.push(["Vary", ["Origin", "Access-Control-Request-Headers"]])
			} else if (o.path.startsWith("/oauth")) {
				rh.push(["Access-Control-Allow-Headers", ["Authorization", "Content-Type"]])
				rh.push(["Access-Control-Allow-Methods", ["GET", "POST"]])
				rh.push(["Access-Control-Expose-Headers", ["WWW-Authenticate"]])
				rh.push(["Vary", ["Origin"]])
			}

			void t.test("allows single configured origin", async(t) => {
				let e: object = {
					...o.env,
					DOCSPACE_SERVER_CORS_OAUTH_ORIGIN: "http://localhost",
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let i: RequestInit = {
					method: "OPTIONS",
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				check(res.v, rh)

				i = {
					method: "OPTIONS",
					headers: {
						Origin: "http://localhost",
					},
				}

				res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				check(res.v, rh)

				assert.ok(res.v.headers.get("Access-Control-Allow-Origin") === "http://localhost")
			})

			void t.test("allows multiple configured origins", async(t) => {
				let e: object = {
					...o.env,
					DOCSPACE_SERVER_CORS_OAUTH_ORIGIN: "http://localhost:8001,http://localhost:8002",
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let i: RequestInit = {
					method: "OPTIONS",
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				check(res.v, rh)

				i = {
					method: "OPTIONS",
					headers: {
						Origin: "http://localhost:8001",
					},
				}

				res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				check(res.v, rh)

				assert.ok(res.v.headers.get("Access-Control-Allow-Origin") === "http://localhost:8001")

				i = {
					method: "OPTIONS",
					headers: {
						Origin: "http://localhost:8002",
					},
				}

				res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				check(res.v, rh)

				assert.ok(res.v.headers.get("Access-Control-Allow-Origin") === "http://localhost:8002")
			})

			let ca: [string, string[]][] = [
				["Access-Control-Allow-Origin", ["*"]],
				["Access-Control-Max-Age", ["3600"]],
				["Content-Length", ["0"]],
			]

			if (o.path.startsWith("/.well-known")) {
				ca.push(["Access-Control-Allow-Methods", ["GET"]])
				ca.push(["Vary", ["Access-Control-Request-Headers"]])
			} else if (o.path.startsWith("/oauth")) {
				ca.push(["Access-Control-Allow-Headers", ["Authorization", "Content-Type"]])
				ca.push(["Access-Control-Allow-Methods", ["GET", "POST"]])
				ca.push(["Access-Control-Expose-Headers", ["WWW-Authenticate"]])
			}

			void t.test("respects custom max age setting", async(t) => {
				let e: object = {
					...o.env,
					DOCSPACE_SERVER_CORS_OAUTH_MAX_AGE: "3600000",
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let i: RequestInit = {
					method: "OPTIONS",
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				check(res.v, ca)
			})

			void t.test("returns error for OPTIONS preflight when cors is disabled", async(t) => {
				let e: object = {
					...o.env,
					DOCSPACE_SERVER_CORS_OAUTH_ORIGIN: "",
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let i: RequestInit = {
					method: "OPTIONS",
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status !== 204)

				assert.ok(res.v.headers.get("Allow") === o.method)
			})
		})
	}

	type TestMethodNotAllowedOptions = {
		env: object
		path: string
		allowed: string
	}

	let testMethodNotAllowed = (t: test.TestContext, o: TestMethodNotAllowedOptions): void => {
		void t.test("method not allowed", async(t) => {
			let a = await setup(t, o.env)

			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			let ta: string[] = [
				"DELETE",
				"GET",
				"PATCH",
				"POST",
				"PUT",
			]

			for (let tt of ta) {
				if (tt !== o.allowed) {
					void t.test(`method ${tt} not allowed`, async() => {
						let i: RequestInit = {
							method: tt,
						}

						let res = await r.safeAsync(fetch, u.v, i)
						assert.ok(res.err === undefined)

						assert.ok(res.v.status === 405)

						let ab = await readFetchJson(res.v)
						assert.ok(ab.err === undefined)

						let eb: object = {
							error: "invalid_request",
							error_description: "Method Not Allowed",
						}

						assert.deepEqual(ab.v, eb)
					})
				}
			}
		})
	}

	type TestUnsupportedMediaTypeOptions = {
		env: object
		method: string
		path: string
	}

	let testUnsupportedMediaType = (
		t: test.TestContext,
		o: TestUnsupportedMediaTypeOptions,
	): void => {
		let check = async(res: Response): Promise<void> => {
			assert.ok(res.status === 415)

			let ab = await readFetchJson(res)
			assert.ok(ab.err === undefined)

			let eb: object = {
				error: "invalid_request",
				error_description: "Unsupported Media Type",
			}

			assert.deepEqual(ab.v, eb)
		}

		void t.test("unsupported media type", async(t) => {
			let a = await setup(t, o.env)

			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			void t.test("rejects request with unsupported Content-Type header", async() => {
				let i: RequestInit = {
					method: o.method,
					headers: {
						"Content-Type": "application/text",
					},
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				await check(res.v)
			})

			void t.test("rejects request without Content-Type header", async() => {
				let i: RequestInit = {
					method: o.method,
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				await check(res.v)
			})
		})
	}

	type TestRateLimitOptions = {
		env: object
		method: string
		path: string
		contentType: string
		defaultCapacity: number
		defaultWindow: number
		capacityEnv: string
		windowEnv: string
	}

	let testRateLimit = (t: test.TestContext, o: TestRateLimitOptions): void => {
		type checkOptions = {
			limit: string | null
			policy: string | null
			remaining: string | null
			reset: string | null
			after: string | null
		}

		let check = (h: Headers, o: checkOptions): void => {
			let eh = h.get("Access-Control-Expose-Headers")
			assert.ok(eh)

			let aa = eh.split(",")

			let ea: string[] = [
				"RateLimit-Limit",
				"RateLimit-Policy",
				"RateLimit-Remaining",
				"RateLimit-Reset",
				"Retry-After",
			]

			for (let h of ea) {
				assert.ok(aa.includes(h))
			}

			assert.ok(h.get("RateLimit-Limit") === o.limit)
			assert.ok(h.get("RateLimit-Policy") === o.policy)
			assert.ok(h.get("RateLimit-Remaining") === o.remaining)
			assert.ok(h.get("RateLimit-Reset") === o.reset)
			assert.ok(h.get("Retry-After") === o.after)
		}

		let request = async(a: net.AddressInfo): Promise<Response> => {
			let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
			assert.ok(u.err === undefined)

			let i: RequestInit = {
				method: o.method,
			}

			if (o.contentType) {
				i.headers = {
					"Content-Type": o.contentType,
				}
			}

			let res = await r.safeAsync(fetch, u.v, i)
			assert.ok(res.err === undefined)

			return res.v
		}

		void t.test("rate limit", (t) => {
			void t.test("applies default rate limit headers", async(t) => {
				let a = await setup(t, o.env)

				let res = await request(a)

				let co: checkOptions = {
					limit: `${o.defaultCapacity}`,
					policy: `${o.defaultCapacity};w=${o.defaultWindow / 1000}`,
					remaining: `${o.defaultCapacity - 1}`,
					reset: `${o.defaultWindow / 1000}`,
					after: null,
				}

				check(res.headers, co)
			})

			void t.test("applies custom rate limit headers", async(t) => {
				let e: object = {
					...o.env,
					[o.capacityEnv]: "100",
					[o.windowEnv]: "30000",
				}

				let a = await setup(t, e)

				let res = await request(a)

				let co: checkOptions = {
					limit: "100",
					policy: "100;w=30",
					remaining: "99",
					reset: "30",
					after: null,
				}

				check(res.headers, co)
			})

			void t.test("omits rate limit headers when disabled", async(t) => {
				let e: object = {
					...o.env,
					[o.capacityEnv]: "0",
					[o.windowEnv]: "0",
				}

				let a = await setup(t, e)

				let res = await request(a)

				let co: checkOptions = {
					limit: null,
					policy: null,
					remaining: null,
					reset: null,
					after: null,
				}

				check(res.headers, co)
			})

			void t.test("blocks request after exceeding rate limit", async(t) => {
				let e: object = {
					...o.env,
					[o.capacityEnv]: "1",
					[o.windowEnv]: "60000",
				}

				let a = await setup(t, e)

				let res = await request(a)

				let co: checkOptions = {
					limit: "1",
					policy: "1;w=60",
					remaining: "0",
					reset: "60",
					after: null,
				}

				check(res.headers, co)

				res = await request(a)

				co = {
					limit: "1",
					policy: "1;w=60",
					remaining: "0",
					reset: "60",
					after: "60",
				}

				assert.ok(res.status === 429)

				check(res.headers, co)

				let ab = await readFetchJson(res)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "too_many_requests",
					error_description: "Too Many Requests",
				}

				assert.deepEqual(ab.v, eb)
			})
		})
	}

	type TestClientAuthErrorHandlingOptions = {
		path: string
	}

	let testClientAuthErrorHandling = (
		t: test.TestContext,
		o: TestClientAuthErrorHandlingOptions,
	): void => {
		void t.test("client authentication error handling", (t) => {
			void t.test("returns error when Authorization header is malformed", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Authorization": "v",
						"Content-Type": "application/x-www-form-urlencoded",
					},
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 401)

				assert.ok(res.v.headers.get("WWW-Authenticate") === 'Basic realm="OAuth"')

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_client",
					error_description: "Parsing header\n" +
						"\tMalformed header",
				}

				assert.deepEqual(ab.v, eb)
			})

			void t.test("returns error when Authorization header has invalid scheme", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Authorization": "v v",
						"Content-Type": "application/x-www-form-urlencoded",
					},
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 401)

				assert.ok(res.v.headers.get("WWW-Authenticate") === 'Basic realm="OAuth"')

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_client",
					error_description: "Parsing header\n" +
						"\tInvalid scheme",
				}

				assert.deepEqual(ab.v, eb)
			})

			void t.test("returns error when Authorization header has malformed password", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Authorization": "Basic v",
						"Content-Type": "application/x-www-form-urlencoded",
					},
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 401)

				assert.ok(res.v.headers.get("WWW-Authenticate") === 'Basic realm="OAuth"')

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_client",
					error_description: "Parsing header\n" +
						"\tMalformed password",
				}

				assert.deepEqual(ab.v, eb)
			})

			void t.test("returns error when Authorization header is missing client_id", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let p = Buffer.from(":").toString("base64")

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Authorization": `Basic ${p}`,
						"Content-Type": "application/x-www-form-urlencoded",
					},
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 401)

				assert.ok(res.v.headers.get("WWW-Authenticate") === 'Basic realm="OAuth"')

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_client",
					error_description: "Parsing header\n" +
						"\tNo client_id",
				}

				assert.deepEqual(ab.v, eb)
			})

			void t.test("returns error when Authorization header is missing client_secret", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let p = Buffer.from("xxx:").toString("base64")

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Authorization": `Basic ${p}`,
						"Content-Type": "application/x-www-form-urlencoded",
					},
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 401)

				assert.ok(res.v.headers.get("WWW-Authenticate") === 'Basic realm="OAuth"')

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_client",
					error_description: "Parsing header\n" +
						"\tNo client_secret",
				}

				assert.deepEqual(ab.v, eb)
			})

			void t.test("returns error when both Authorization header and client_id in body provided", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let p = Buffer.from("xxx:yyy").toString("base64")

				let f = new URLSearchParams()

				f.set("client_id", "xxx")

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Authorization": `Basic ${p}`,
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "Multiple authentication methods",
				}

				assert.deepEqual(ab.v, eb)
			})

			void t.test("returns error when both Authorization header and client_secret in body provided", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let p = Buffer.from("xxx:yyy").toString("base64")

				let f = new URLSearchParams()

				f.set("client_secret", "yyy")

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Authorization": `Basic ${p}`,
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "Multiple authentication methods",
				}

				assert.deepEqual(ab.v, eb)
			})

			void t.test("returns error when both Authorization header and client credentials in body provided", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let p = Buffer.from("xxx:yyy").toString("base64")

				let f = new URLSearchParams()

				f.set("client_id", "xxx")
				f.set("client_secret", "yyy")

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Authorization": `Basic ${p}`,
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "Multiple authentication methods",
				}

				assert.deepEqual(ab.v, eb)
			})

			void t.test("returns error when client_id is missing from body with environment credentials configured", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_CLIENT_ID: "xxx",
					DOCSPACE_OAUTH_CLIENT_SECRET: "yyy",
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "Parsing body\n" +
						"\t\tclient_id: invalid_type Invalid input: expected string, received undefined",
				}

				assert.deepEqual(ab.v, eb)
			})

			void t.test("returns error when client_id in body mismatches environment credentials", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_CLIENT_ID: "xxx",
					DOCSPACE_OAUTH_CLIENT_SECRET: "yyy",
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				f.set("client_id", "zzz")

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 401)

				assert.ok(res.v.headers.get("WWW-Authenticate") === 'Basic realm="OAuth"')

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_client",
					error_description: "Client ID mismatch",
				}

				assert.deepEqual(ab.v, eb)
			})

			void t.test("returns error when client credentials are missing from body", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "Parsing body\n" +
						"\t\tclient_id: invalid_type Invalid input: expected string, received undefined\n" +
						"\t\tclient_secret: invalid_type Invalid input: expected string, received undefined",
				}

				assert.deepEqual(ab.v, eb)
			})
		})
	}

	type TestClientAuthOptions = {
		skipCredentials: boolean
		path: string
		body: Record<string, string>
	}

	let testClientAuth = (t: test.TestContext, o: TestClientAuthOptions): void => {
		let listener = (): AsyncRequestListener => {
			return async(req, res) => {
				if (!o.skipCredentials) {
					let ab = await readHttpForm(req)
					assert.ok(ab.err === undefined)

					let eb: object = {
						client_id: "xxx",
						client_secret: "yyy",
					}

					assert.partialDeepStrictEqual(ab.v, eb)
				}

				res.end()
			}
		}

		void t.test("client authentication", (t) => {
			void t.test("authenticates client via Authorization header", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn(listener())

				let hp = onRequest(t, hs, hl)

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
					assert.ok(u.err === undefined)

					let p = Buffer.from("xxx:yyy").toString("base64")

					let f = new URLSearchParams()

					for (let [k, v] of Object.entries(o.body)) {
						f.set(k, v)
					}

					let i: RequestInit = {
						method: "POST",
						headers: {
							"Authorization": `BaSiC ${p}`,
							"Content-Type": "application/x-www-form-urlencoded",
						},
						body: f.toString(),
					}

					let res = await r.safeAsync(fetch, u.v, i)
					assert.ok(res.err === undefined)
				}

				await Promise.race([hp, tf()])

				assert.ok(hl.mock.callCount() === 1)
			})

			void t.test("authenticates client via client_id in body when configured in environment", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn(listener())

				let hp = onRequest(t, hs, hl)

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_CLIENT_ID: "xxx",
						DOCSPACE_OAUTH_CLIENT_SECRET: "yyy",
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
					assert.ok(u.err === undefined)

					let f = new URLSearchParams()

					f.set("client_id", "xxx")

					for (let [k, v] of Object.entries(o.body)) {
						f.set(k, v)
					}

					let i: RequestInit = {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
						},
						body: f.toString(),
					}

					let res = await r.safeAsync(fetch, u.v, i)
					assert.ok(res.err === undefined)
				}

				await Promise.race([hp, tf()])

				assert.ok(hl.mock.callCount() === 1)
			})

			void t.test("authenticates client via client_id and client_secret in body when configured in environment", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn(listener())

				let hp = onRequest(t, hs, hl)

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_CLIENT_ID: "xxx",
						DOCSPACE_OAUTH_CLIENT_SECRET: "yyy",
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
					assert.ok(u.err === undefined)

					let f = new URLSearchParams()

					f.set("client_id", "xxx")
					f.set("client_secret", "yyy")

					for (let [k, v] of Object.entries(o.body)) {
						f.set(k, v)
					}

					let i: RequestInit = {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
						},
						body: f.toString(),
					}

					let res = await r.safeAsync(fetch, u.v, i)
					assert.ok(res.err === undefined)
				}

				await Promise.race([hp, tf()])

				assert.ok(hl.mock.callCount() === 1)
			})

			void t.test("authenticates client via client_id and client_secret in body", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn(listener())

				let hp = onRequest(t, hs, hl)

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
					assert.ok(u.err === undefined)

					let f = new URLSearchParams()

					f.set("client_id", "xxx")
					f.set("client_secret", "yyy")

					for (let [k, v] of Object.entries(o.body)) {
						f.set(k, v)
					}

					let i: RequestInit = {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
						},
						body: f.toString(),
					}

					let res = await r.safeAsync(fetch, u.v, i)
					assert.ok(res.err === undefined)
				}

				await Promise.race([hp, tf()])

				assert.ok(hl.mock.callCount() === 1)
			})
		})
	}

	type TestUserAgentOptions = {
		path: string
		body: Record<string, string>
	}

	let testUserAgent = (t: test.TestContext, o: TestUserAgentOptions): void => {
		void t.test("user agent", (t) => {
			void t.test("uses default User-Agent", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn<AsyncRequestListener>((req, res) => {
					assert.ok(req.headers["user-agent"] === `${meta.name} v${meta.version}`)

					res.end()
				})

				let hp = onRequest(t, hs, hl)

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
					assert.ok(u.err === undefined)

					let f = new URLSearchParams()

					for (let [k, v] of Object.entries(o.body)) {
						f.set(k, v)
					}

					let i: RequestInit = {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
						},
						body: f.toString(),
					}

					let fetch = withAuth(globalThis.fetch)

					let res = await r.safeAsync(fetch, u.v, i)
					assert.ok(res.err === undefined)
				}

				await Promise.race([hp, tf()])

				assert.ok(hl.mock.callCount() === 1)
			})

			void t.test("uses custom User-Agent", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn<AsyncRequestListener>((req, res) => {
					assert.ok(req.headers["user-agent"] === "test")

					res.end()
				})

				let hp = onRequest(t, hs, hl)

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_USER_AGENT: "test",
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
					assert.ok(u.err === undefined)

					let f = new URLSearchParams()

					for (let [k, v] of Object.entries(o.body)) {
						f.set(k, v)
					}

					let i: RequestInit = {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
						},
						body: f.toString(),
					}

					let fetch = withAuth(globalThis.fetch)

					let res = await r.safeAsync(fetch, u.v, i)
					assert.ok(res.err === undefined)
				}

				await Promise.race([hp, tf()])

				assert.ok(hl.mock.callCount() === 1)
			})
		})
	}

	type TestProxyHeaderForwardingOptions = {
		path: string
		body: Record<string, string>
	}

	let testProxyHeaderForwarding = (
		t: test.TestContext,
		o: TestProxyHeaderForwardingOptions,
	): void => {
		void t.test("proxy header forwarding", (t) => {
			void t.test("sets X-Forwarded-For and X-Real-IP from client IP", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn<AsyncRequestListener>((req, res) => {
					assert.ok(req.headers["x-forwarded-for"] === "::1")
					assert.ok(req.headers["x-real-ip"] === "::1")

					res.end()
				})

				let hp = onRequest(t, hs, hl)

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
					assert.ok(u.err === undefined)

					let f = new URLSearchParams()

					for (let [k, v] of Object.entries(o.body)) {
						f.set(k, v)
					}

					let i: RequestInit = {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
						},
						body: f.toString(),
					}

					let fetch = withAuth(globalThis.fetch)

					let res = await r.safeAsync(fetch, u.v, i)
					assert.ok(res.err === undefined)
				}

				await Promise.race([hp, tf()])

				assert.ok(hl.mock.callCount() === 1)
			})

			void t.test("extends X-Forwarded-For preserving X-Real-IP", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn<AsyncRequestListener>((req, res) => {
					assert.ok(req.headers["x-forwarded-for"] === "203.0.113.195, 2001:db8:85a3:8d3:1319:8a2e:370:7348, ::1")
					assert.ok(req.headers["x-real-ip"] === "203.0.113.190")

					res.end()
				})

				let hp = onRequest(t, hs, hl)

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
					assert.ok(u.err === undefined)

					let f = new URLSearchParams()

					for (let [k, v] of Object.entries(o.body)) {
						f.set(k, v)
					}

					let i: RequestInit = {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
							"X-Forwarded-For": "203.0.113.195, 2001:db8:85a3:8d3:1319:8a2e:370:7348",
							"X-Real-IP": "203.0.113.190",
						},
						body: f.toString(),
					}

					let fetch = withAuth(globalThis.fetch)

					let res = await r.safeAsync(fetch, u.v, i)
					assert.ok(res.err === undefined)
				}

				await Promise.race([hp, tf()])

				assert.ok(hl.mock.callCount() === 1)
			})
		})
	}

	type TestProxyErrorHandlingOptions = {
		path: string
		body: Record<string, string>
	}

	let testProxyErrorHandling = (t: test.TestContext, o: TestProxyErrorHandlingOptions): void => {
		void t.test("proxy error handling", (t) => {
			void t.test("passes through upstream error response", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					let b: object = {
						error: "some_error",
						error_description: "some_description",
						error_uri: "some_uri",
					}

					let s = await sendJson(res, 418, b)
					assert.ok(s.err === undefined)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
					assert.ok(u.err === undefined)

					let f = new URLSearchParams()

					for (let [k, v] of Object.entries(o.body)) {
						f.set(k, v)
					}

					let i: RequestInit = {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
						},
						body: f.toString(),
					}

					let fetch = withAuth(globalThis.fetch)

					let res = await r.safeAsync(fetch, u.v, i)
					assert.ok(res.err === undefined)

					assert.ok(res.v.status === 418)

					let ab = await readFetchJson(res.v)
					assert.ok(ab.err === undefined)

					let eb: object = {
						error: "some_error",
						error_description: "some_description",
						error_uri: "some_uri",
					}

					assert.deepEqual(ab.v, eb)
				}

				await Promise.race([hp, tf()])
			})

			void t.test("transforms upstream custom error to protocol error", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					let b: object = {
						reason: "some_reason",
					}

					let s = await sendJson(res, 418, b)
					assert.ok(s.err === undefined)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let u = r.safeNew(URL, o.path, `http://[${a.address}]:${a.port}/`)
					assert.ok(u.err === undefined)

					let f = new URLSearchParams()

					for (let [k, v] of Object.entries(o.body)) {
						f.set(k, v)
					}

					let i: RequestInit = {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
						},
						body: f.toString(),
					}

					let fetch = withAuth(globalThis.fetch)

					let res = await r.safeAsync(fetch, u.v, i)
					assert.ok(res.err === undefined)

					assert.ok(res.v.status === 418)

					let ab = await readFetchJson(res.v)
					assert.ok(ab.err === undefined)

					let eb: object = {
						error: "server_error",
						error_description: "some_reason",
					}

					assert.deepEqual(ab.v, eb)
				}

				await Promise.race([hp, tf()])
			})
		})
	}

	void t.test("/.well-known/oauth-authorization-server", (t) => {
		let co: TestCorsOptions = {
			env: {},
			method: "GET",
			path: "/.well-known/oauth-authorization-server",
		}

		testCors(t, co)

		let mo: TestMethodNotAllowedOptions = {
			env: {},
			path: "/.well-known/oauth-authorization-server",
			allowed: "GET",
		}

		testMethodNotAllowed(t, mo)

		let ro: TestRateLimitOptions = {
			env: {},
			method: "GET",
			path: "/.well-known/oauth-authorization-server",
			contentType: "",
			defaultCapacity: 200,
			defaultWindow: 60000,
			capacityEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_SERVER_METADATA_CAPACITY",
			windowEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_SERVER_METADATA_WINDOW",
		}

		testRateLimit(t, ro)

		void t.test("server metadata", (t) => {
			void t.test("returns server metadata without dynamic client registration", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/.well-known/oauth-authorization-server", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let res = await r.safeAsync(fetch, u.v)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 200)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					issuer: `http://[${a.address}]:${a.port}`,
					authorization_endpoint: `http://[${a.address}]:${a.port}/oauth/authorize`,
					token_endpoint: `http://[${a.address}]:${a.port}/oauth/token`,
					response_types_supported: [
						"code",
					],
					grant_types_supported: [
						"authorization_code",
						"refresh_token",
					],
					token_endpoint_auth_methods_supported: [
						"client_secret_basic",
						"client_secret_post",
					],
					revocation_endpoint: `http://[${a.address}]:${a.port}/oauth/revoke`,
					revocation_endpoint_auth_methods_supported: [
						"client_secret_basic",
						"client_secret_post",
					],
					introspection_endpoint: `http://[${a.address}]:${a.port}/oauth/introspect`,
					introspection_endpoint_auth_methods_supported: [
						"client_secret_basic",
						"client_secret_post",
					],
					code_challenge_methods_supported: [
						"S256",
					],
				}

				assert.deepEqual(ab.v, eb)
			})

			void t.test("returns server metadata with dynamic client registration", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_CLIENT_ID: "xxx",
					DOCSPACE_OAUTH_CLIENT_SECRET: "yyy",
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, "/.well-known/oauth-authorization-server", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let res = await r.safeAsync(fetch, u.v)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 200)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					issuer: `http://[${a.address}]:${a.port}`,
					authorization_endpoint: `http://[${a.address}]:${a.port}/oauth/authorize`,
					token_endpoint: `http://[${a.address}]:${a.port}/oauth/token`,
					registration_endpoint: `http://[${a.address}]:${a.port}/oauth/register`,
					response_types_supported: [
						"code",
					],
					grant_types_supported: [
						"authorization_code",
						"refresh_token",
					],
					token_endpoint_auth_methods_supported: [
						"client_secret_basic",
						"client_secret_post",
						"none",
					],
					revocation_endpoint: `http://[${a.address}]:${a.port}/oauth/revoke`,
					revocation_endpoint_auth_methods_supported: [
						"client_secret_basic",
						"client_secret_post",
						"none",
					],
					introspection_endpoint: `http://[${a.address}]:${a.port}/oauth/introspect`,
					introspection_endpoint_auth_methods_supported: [
						"client_secret_basic",
						"client_secret_post",
						"none",
					],
					code_challenge_methods_supported: [
						"S256",
					],
				}

				assert.deepEqual(ab.v, eb)
			})
		})
	})

	void t.test("/.well-known/oauth-protected-resource", (t) => {
		let co: TestCorsOptions = {
			env: {},
			method: "GET",
			path: "/.well-known/oauth-protected-resource",
		}

		testCors(t, co)

		let mo: TestMethodNotAllowedOptions = {
			env: {},
			path: "/.well-known/oauth-protected-resource",
			allowed: "GET",
		}

		testMethodNotAllowed(t, mo)

		let ro: TestRateLimitOptions = {
			env: {},
			method: "GET",
			path: "/.well-known/oauth-protected-resource",
			contentType: "",
			defaultCapacity: 200,
			defaultWindow: 60000,
			capacityEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_RESOURCE_METADATA_CAPACITY",
			windowEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_RESOURCE_METADATA_WINDOW",
		}

		testRateLimit(t, ro)

		void t.test("resource metadata", (t) => {
			void t.test("returns resource metadata", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/.well-known/oauth-protected-resource", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let res = await r.safeAsync(fetch, u.v)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 200)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					resource: `http://[${a.address}]:${a.port}`,
					authorization_servers: [
						`http://[${a.address}]:${a.port}/oauth/authorize`,
					],
					bearer_methods_supported: [
						"header",
					],
				}

				assert.deepEqual(ab.v, eb)
			})
		})
	})

	void t.test("/oauth/authorize", (t) => {
		let co: TestCorsOptions = {
			env: {},
			method: "GET",
			path: "/oauth/authorize",
		}

		testCors(t, co)

		let mo: TestMethodNotAllowedOptions = {
			env: {},
			path: "/oauth/authorize",
			allowed: "GET",
		}

		testMethodNotAllowed(t, mo)

		let ro: TestRateLimitOptions = {
			env: {},
			method: "GET",
			path: "/oauth/authorize",
			contentType: "",
			defaultCapacity: 200,
			defaultWindow: 60000,
			capacityEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_AUTHORIZE_CAPACITY",
			windowEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_AUTHORIZE_WINDOW",
		}

		testRateLimit(t, ro)

		void t.test("error handling", (t) => {
			void t.test("returns error when query parameters are missing", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/oauth/authorize", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let res = await r.safeAsync(fetch, u.v)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "Parsing query\n" +
						'\t\tresponse_type: invalid_value Invalid input: expected "code"\n' +
						"\t\tclient_id: invalid_type Invalid input: expected string, received undefined",
				}

				assert.deepEqual(ab.v, eb)
			})

			void t.test("returns error when response_type is invalid", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/oauth/authorize", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let q = new URLSearchParams()

				q.set("response_type", "invalid")
				q.set("client_id", "xxx")

				u.v.search = q.toString()

				let res = await r.safeAsync(fetch, u.v)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "Parsing query\n" +
						'\t\tresponse_type: invalid_value Invalid input: expected "code"',
				}

				assert.deepEqual(ab.v, eb)
			})

			void t.test("returns error when redirect_uri is missing", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/oauth/authorize", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let q = new URLSearchParams()

				q.set("response_type", "code")
				q.set("client_id", "xxx")

				u.v.search = q.toString()

				let res = await r.safeAsync(fetch, u.v)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "No redirect URI",
				}

				assert.deepEqual(ab.v, eb)
			})
		})

		void t.test("redirect", (t) => {
			void t.test("redirects to upstream", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: "http://localhost:8020/",
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, "/oauth/authorize", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let q = new URLSearchParams()

				q.set("response_type", "code")
				q.set("client_id", "xxx")
				q.set("redirect_uri", "http://localhost:8030")

				u.v.search = q.toString()

				let i: RequestInit = {
					redirect: "manual",
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 302)

				let l = parseFetchLocation(res.v)
				assert.ok(l.err === undefined)

				assert.ok(`${l.v.origin}${l.v.pathname}` === "http://localhost:8020/oauth2/authorize")

				let aq = Object.fromEntries(l.v.searchParams.entries())

				let eq: object = {
					client_id: "xxx",
					redirect_uri: `http://[${a.address}]:${a.port}/oauth/callback`,
					response_type: "code",
					state: aq.state,
				}

				assert.deepEqual(aq, eq)

				let ab = await readFetchText(res.v)
				assert.ok(ab.err === undefined)

				assert.ok(ab.v === `Found. Redirecting to ${l.v}`)
			})
		})

		void t.test("state token signature algorithm", (t) => {
			void t.test("signs state token with HS256 algorithm by default", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_STATE_TOKEN_SECRET_KEY: "yyy",
				}

				let a = await setup(t, e)

				let q = new URLSearchParams()

				let s = await requestState(a, q)

				checkJwtAlg(s, "HS256", "yyy")
			})

			let ta: jwt.Algorithm[] = [
				"HS256",
				"HS384",
				"HS512",
			]

			for (let tt of ta) {
				void t.test(`signs state token with ${tt} algorithm`, async(t) => {
					let e: object = {
						DOCSPACE_OAUTH_STATE_TOKEN_ALGORITHM: tt,
						DOCSPACE_OAUTH_STATE_TOKEN_SECRET_KEY: "yyy",
					}

					let a = await setup(t, e)

					let q = new URLSearchParams()

					let s = await requestState(a, q)

					checkJwtAlg(s, tt, "yyy")
				})
			}

			void t.test("signs state token without signature when algorithm is disabled", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_STATE_TOKEN_ALGORITHM: "",
					DOCSPACE_OAUTH_STATE_TOKEN_SECRET_KEY: "",
				}

				let a = await setup(t, e)

				let q = new URLSearchParams()

				let s = await requestState(a, q)

				checkJwtAlg(s, "none", "")
			})
		})

		void t.test("state token expiration time", (t) => {
			void t.test("sets default state token expiration", async(t) => {
				let a = await setup(t, {})

				let q = new URLSearchParams()

				let s = await requestState(a, q)

				checkJwtTtl(s, 3600000)
			})

			void t.test("sets custom state token expiration", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_STATE_TOKEN_TTL: 1800000,
				}

				let a = await setup(t, e)

				let q = new URLSearchParams()

				let s = await requestState(a, q)

				checkJwtTtl(s, 1800000)
			})

			void t.test("creates state token without expiration when ttl is disabled", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_STATE_TOKEN_TTL: 0,
				}

				let a = await setup(t, e)

				let q = new URLSearchParams()

				let s = await requestState(a, q)

				checkJwtTtl(s, 0)
			})
		})

		void t.test("state token payload", (t) => {
			void t.test("embeds redirect_uri in state token payload", async(t) => {
				let a = await setup(t, {})

				let q = new URLSearchParams()

				q.set("redirect_uri", "http://localhost:8040")

				let s = await requestState(a, q)

				let p: object = {
					redirect_uri: "http://localhost:8040",
				}

				checkJwtPayload(s, p)
			})

			void t.test("embeds client state in state token payload", async(t) => {
				let a = await setup(t, {})

				let q = new URLSearchParams()

				q.set("state", "data")

				let s = await requestState(a, q)

				let p: object = {
					state: "data",
				}

				checkJwtPayload(s, p)
			})
		})
	})

	void t.test("/oauth/callback", (t) => {
		let co: TestCorsOptions = {
			env: {},
			method: "GET",
			path: "/oauth/callback",
		}

		testCors(t, co)

		let mo: TestMethodNotAllowedOptions = {
			env: {},
			path: "/oauth/callback",
			allowed: "GET",
		}

		testMethodNotAllowed(t, mo)

		let ro: TestRateLimitOptions = {
			env: {},
			method: "GET",
			path: "/oauth/callback",
			contentType: "",
			defaultCapacity: 200,
			defaultWindow: 60000,
			capacityEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_CALLBACK_CAPACITY",
			windowEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_CALLBACK_WINDOW",
		}

		testRateLimit(t, ro)

		void t.test("error handling", (t) => {
			void t.test("returns error when query parameters are missing", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/oauth/callback", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let res = await r.safeAsync(fetch, u.v)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "Parsing query\n" +
						"\t\tcode: invalid_type Invalid input: expected string, received undefined",
				}

				assert.deepEqual(ab.v, eb)
			})

			void t.test("returns error when state parameter is missing", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/oauth/callback", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let q = new URLSearchParams()

				q.set("code", "vvv")

				u.v.search = q.toString()

				let res = await r.safeAsync(fetch, u.v)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "No state",
				}

				assert.deepEqual(ab.v, eb)
			})

			void t.test("returns error when state token is invalid", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/oauth/callback", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let q = new URLSearchParams()

				q.set("code", "vvv")
				q.set("state", "www")

				u.v.search = q.toString()

				let res = await r.safeAsync(fetch, u.v)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "Verifying token\n" +
						"\tVerifying token\n" +
						"\t\tjwt malformed",
				}

				assert.deepEqual(ab.v, eb)
			})
		})

		void t.test("redirect", (t) => {
			void t.test("redirects to upstream preserving client state", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: "http://localhost:8020/",
				}

				let a = await setup(t, e)

				let q = new URLSearchParams()

				q.set("redirect_uri", "http://localhost:8030/app")
				q.set("state", "data")

				let s = await requestState(a, q)

				let u = r.safeNew(URL, "/oauth/callback", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				q = new URLSearchParams()

				q.set("code", "vvv")
				q.set("state", s)

				u.v.search = q.toString()

				let i: RequestInit = {
					redirect: "manual",
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 302)

				let l = parseFetchLocation(res.v)
				assert.ok(l.err === undefined)

				assert.ok(`${l.v.origin}${l.v.pathname}` === "http://localhost:8030/app")

				let aq = Object.fromEntries(l.v.searchParams.entries())

				let eq: Record<string, string> = {
					code: "vvv",
					state: "data",
				}

				assert.deepEqual(aq, eq)

				let ab = await readFetchText(res.v)
				assert.ok(ab.err === undefined)

				assert.ok(ab.v === `Found. Redirecting to ${l.v}`)
			})

			void t.test("redirects to upstream without preserving client state", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: "http://localhost:8020/",
				}

				let a = await setup(t, e)

				let q = new URLSearchParams()

				q.set("redirect_uri", "http://localhost:8030/app")

				let s = await requestState(a, q)

				let u = r.safeNew(URL, "/oauth/callback", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				q = new URLSearchParams()

				q.set("code", "vvv")
				q.set("state", s)

				u.v.search = q.toString()

				let i: RequestInit = {
					redirect: "manual",
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 302)

				let l = parseFetchLocation(res.v)
				assert.ok(l.err === undefined)

				assert.ok(`${l.v.origin}${l.v.pathname}` === "http://localhost:8030/app")

				let aq = Object.fromEntries(l.v.searchParams.entries())

				let eq: Record<string, string> = {
					code: "vvv",
				}

				assert.deepEqual(aq, eq)

				let ab = await readFetchText(res.v)
				assert.ok(ab.err === undefined)

				assert.ok(ab.v === `Found. Redirecting to ${l.v}`)
			})
		})
	})

	void t.test("/oauth/introspect", (t) => {
		let ot = ""
		let wt = ""

		t.before(async(t) => {
			let [hs, ha] = await setupHttp(t)

			let hp = onRequest(t, hs, async(_, res) => {
				ot = await sendAccessToken(_, res)
			})

			let tf = async(): Promise<void> => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
				}

				let a = await setup(t, e)

				wt = await requestAccessToken(a)
			}

			await Promise.race([hp, tf()])
		})

		let co: TestCorsOptions = {
			env: {},
			method: "POST",
			path: "/oauth/introspect",
		}

		testCors(t, co)

		let mo: TestMethodNotAllowedOptions = {
			env: {},
			path: "/oauth/introspect",
			allowed: "POST",
		}

		testMethodNotAllowed(t, mo)

		let to: TestUnsupportedMediaTypeOptions = {
			env: {},
			method: "POST",
			path: "/oauth/introspect",
		}

		testUnsupportedMediaType(t, to)

		let ro: TestRateLimitOptions = {
			env: {},
			method: "POST",
			path: "/oauth/introspect",
			contentType: "application/x-www-form-urlencoded",
			defaultCapacity: 10,
			defaultWindow: 60000,
			capacityEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_INTROSPECT_CAPACITY",
			windowEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_INTROSPECT_WINDOW",
		}

		testRateLimit(t, ro)

		let aeo: TestClientAuthErrorHandlingOptions = {
			path: "/oauth/introspect",
		}

		testClientAuthErrorHandling(t, aeo)

		let ao: TestClientAuthOptions = {
			skipCredentials: true,
			path: "/oauth/introspect",
			body: {
				get token() {
					return wt
				},
			},
		}

		testClientAuth(t, ao)

		let uo: TestUserAgentOptions = {
			path: "/oauth/introspect",
			body: {
				get token() {
					return wt
				},
			},
		}

		testUserAgent(t, uo)

		let ho: TestProxyHeaderForwardingOptions = {
			path: "/oauth/introspect",
			body: {
				get token() {
					return wt
				},
			},
		}

		testProxyHeaderForwarding(t, ho)

		let eo: TestProxyErrorHandlingOptions = {
			path: "/oauth/introspect",
			body: {
				get token() {
					return wt
				},
			},
		}

		testProxyErrorHandling(t, eo)

		void t.test("error handling", (t) => {
			void t.test("returns error when token parameter is missing", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/oauth/introspect", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "Parsing body\n" +
						"\t\ttoken: invalid_type Invalid input: expected string, received undefined",
				}

				assert.deepEqual(ab.v, eb)
			})

			void t.test("returns error when token is invalid", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/oauth/introspect", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				f.set("token", "zzz")

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_token",
					error_description: "Verifying token\n" +
						"\tVerifying token\n" +
						"\t\tjwt malformed",
				}

				assert.deepEqual(ab.v, eb)
			})

			void t.test("returns error when upstream is unreachable", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: "http://localhost:8020/",
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, "/oauth/introspect", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				f.set("token", wt)

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 500)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let d = "Introspecting token\n" +
					"\tMaking request\n" +
					"\t\tMaking bare request\n" +
					"\t\t\tMaking native request\n" +
					"\t\t\t\tfetch failed\n" +
					"\t\t\t\t\t" // there will be a platform-specific fetch error

				assert.ok(ab.v && typeof ab.v === "object")
				assert.deepEqual(Object.keys(ab.v), ["error", "error_description"])
				assert.ok("error" in ab.v && typeof ab.v.error === "string")
				assert.ok(ab.v.error === "server_error")
				assert.ok("error_description" in ab.v && typeof ab.v.error_description === "string")
				assert.ok(ab.v.error_description.startsWith(d))
			})
		})

		void t.test("token forwarding", (t) => {
			void t.test("unwraps and forwards original token to upstream", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn<AsyncRequestListener>(async(req, res) => {
					let ab = await readHttpForm(req)
					assert.ok(ab.err === undefined)

					let eb: object = {
						token: ot,
					}

					assert.partialDeepStrictEqual(ab.v, eb)

					res.end()
				})

				let hp = onRequest(t, hs, hl)

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let u = r.safeNew(URL, "/oauth/introspect", `http://[${a.address}]:${a.port}/`)
					assert.ok(u.err === undefined)

					let f = new URLSearchParams()

					f.set("token", wt)

					let i: RequestInit = {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
						},
						body: f.toString(),
					}

					let fetch = withAuth(globalThis.fetch)

					let res = await r.safeAsync(fetch, u.v, i)
					assert.ok(res.err === undefined)
				}

				await Promise.race([hp, tf()])

				assert.ok(hl.mock.callCount() === 1)
			})
		})

		void t.test("introspection response", (t) => {
			let requestIntrospection = async(a: net.AddressInfo, t: string): Promise<object> => {
				let u = r.safeNew(URL, "/oauth/introspect", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				f.set("token", t)

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 200)

				let b = await readFetchJson(res.v)
				assert.ok(b.err === undefined)

				assert.ok(b.v && typeof b.v === "object")

				return b.v
			}

			let checkExpiration = (b: object, ttl: number): void => {
				assert.ok("exp" in b && typeof b.exp === "number")

				let now = Date.now()

				assert.ok(inDelta(b.exp * 1000, now + ttl, 3000))
			}

			void t.test("returns inactive status for expired token", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					let now = Date.now()

					let p: jwt.JwtPayload = {
						exp: Math.floor((now - 3600000) / 1000),
					}

					let o: jwt.SignOptions = {
						algorithm: "none",
					}

					let t = r.safeSync(jwt.sign, p, "", o)
					assert.ok(t.err === undefined)

					let b: object = {
						access_token: t.v,
						token_type: "test",
					}

					let s = await sendJson(res, 200, b)
					assert.ok(s.err === undefined)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					let ab = await requestIntrospection(a, s)

					let eb: object = {
						active: false,
					}

					assert.deepEqual(ab, eb)
				}

				await Promise.race([hp, tf()])
			})

			void t.test("returns inactive status for not-yet-valid token", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					let now = Date.now()

					let p: jwt.JwtPayload = {
						nbf: Math.floor((now + 3600000) / 1000),
					}

					let o: jwt.SignOptions = {
						algorithm: "none",
					}

					let t = r.safeSync(jwt.sign, p, "", o)
					assert.ok(t.err === undefined)

					let b: object = {
						access_token: t.v,
						token_type: "test",
					}

					let s = await sendJson(res, 200, b)
					assert.ok(s.err === undefined)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					let ab = await requestIntrospection(a, s)

					let eb: object = {
						active: false,
					}

					assert.deepEqual(ab, eb)
				}

				await Promise.race([hp, tf()])
			})

			void t.test("returns active from upstream", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn<AsyncRequestListener>(async(_, res) => {
					switch (hl.mock.callCount()) {
					case 0:
						await sendAccessToken(_, res)
						break

					case 1:
						let b: object = {
							active: false,
						}

						let s = await sendJson(res, 200, b)
						assert.ok(s.err === undefined)

						break

					default:
						assert.fail()
					}
				})

				let hp = onRequest(t, hs, hl)

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					let ab = await requestIntrospection(a, s)

					let eb: object = {
						active: false,
					}

					assert.deepEqual(ab, eb)
				}

				await Promise.race([hp, tf()])
			})

			void t.test("uses minimum expiration when both token and upstream have expiration", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn<AsyncRequestListener>(async(_, res) => {
					switch (hl.mock.callCount()) {
					case 0: {
						let now = Date.now()

						let p: jwt.JwtPayload = {
							exp: Math.floor((now + 3600000) / 1000),
						}

						let o: jwt.SignOptions = {
							algorithm: "none",
						}

						let t = r.safeSync(jwt.sign, p, "", o)
						assert.ok(t.err === undefined)

						let b: object = {
							access_token: t.v,
							token_type: "test",
						}

						let s = await sendJson(res, 200, b)
						assert.ok(s.err === undefined)

						break
					}

					case 1: {
						let now = Date.now()

						let b: object = {
							active: true,
							exp: Math.floor((now + 7200000) / 1000),
						}

						let s = await sendJson(res, 200, b)
						assert.ok(s.err === undefined)

						break
					}

					default:
						assert.fail()
					}
				})

				let hp = onRequest(t, hs, hl)

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
						DOCSPACE_OAUTH_AUTH_TOKEN_TTL: 0,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					let b = await requestIntrospection(a, s)

					checkExpiration(b, 3600000)
				}

				await Promise.race([hp, tf()])
			})

			void t.test("uses upstream expiration when token has no expiration", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn<AsyncRequestListener>(async(_, res) => {
					switch (hl.mock.callCount()) {
					case 0:
						await sendAccessToken(_, res)
						break

					case 1:
						let now = Date.now()

						let b: object = {
							active: true,
							exp: Math.floor((now + 7200000) / 1000),
						}

						let s = await sendJson(res, 200, b)
						assert.ok(s.err === undefined)

						break

					default:
						assert.fail()
					}
				})

				let hp = onRequest(t, hs, hl)

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
						DOCSPACE_OAUTH_AUTH_TOKEN_TTL: 0,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					let b = await requestIntrospection(a, s)

					checkExpiration(b, 7200000)
				}

				await Promise.race([hp, tf()])
			})

			void t.test("uses token expiration when upstream has no expiration", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn<AsyncRequestListener>(async(_, res) => {
					switch (hl.mock.callCount()) {
					case 0: {
						let now = Date.now()

						let p: jwt.JwtPayload = {
							exp: Math.floor((now + 3600000) / 1000),
						}

						let o: jwt.SignOptions = {
							algorithm: "none",
						}

						let t = r.safeSync(jwt.sign, p, "", o)
						assert.ok(t.err === undefined)

						let b: object = {
							access_token: t.v,
							token_type: "test",
						}

						let s = await sendJson(res, 200, b)
						assert.ok(s.err === undefined)

						break
					}

					case 1: {
						let b: object = {
							active: true,
						}

						let s = await sendJson(res, 200, b)
						assert.ok(s.err === undefined)

						break
					}

					default:
						assert.fail()
					}
				})

				let hp = onRequest(t, hs, hl)

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
						DOCSPACE_OAUTH_AUTH_TOKEN_TTL: 0,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					let b = await requestIntrospection(a, s)

					checkExpiration(b, 3600000)
				}

				await Promise.race([hp, tf()])
			})

			void t.test("omits expiration when neither token nor upstream have expiration", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn<AsyncRequestListener>(async(_, res) => {
					switch (hl.mock.callCount()) {
					case 0:
						await sendAccessToken(_, res)
						break

					case 1:
						let b: object = {
							active: true,
						}

						let s = await sendJson(res, 200, b)
						assert.ok(s.err === undefined)

						break

					default:
						assert.fail()
					}
				})

				let hp = onRequest(t, hs, hl)

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
						DOCSPACE_OAUTH_AUTH_TOKEN_TTL: 0,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					let ab = await requestIntrospection(a, s)

					let eb: object = {
						active: true,
					}

					assert.deepEqual(ab, eb)
				}

				await Promise.race([hp, tf()])
			})
		})
	})

	void t.test("/oauth/register", (t) => {
		let co: TestCorsOptions = {
			env: {
				DOCSPACE_OAUTH_CLIENT_ID: "xxx",
				DOCSPACE_OAUTH_CLIENT_SECRET: "yyy",
			},
			method: "POST",
			path: "/oauth/register",
		}

		testCors(t, co)

		let mo: TestMethodNotAllowedOptions = {
			env: {
				DOCSPACE_OAUTH_CLIENT_ID: "xxx",
				DOCSPACE_OAUTH_CLIENT_SECRET: "yyy",
			},
			path: "/oauth/register",
			allowed: "POST",
		}

		testMethodNotAllowed(t, mo)

		let to: TestUnsupportedMediaTypeOptions = {
			env: {
				DOCSPACE_OAUTH_CLIENT_ID: "xxx",
				DOCSPACE_OAUTH_CLIENT_SECRET: "yyy",
			},
			method: "POST",
			path: "/oauth/register",
		}

		testUnsupportedMediaType(t, to)

		let ro: TestRateLimitOptions = {
			env: {
				DOCSPACE_OAUTH_CLIENT_ID: "xxx",
				DOCSPACE_OAUTH_CLIENT_SECRET: "yyy",
			},
			method: "POST",
			path: "/oauth/register",
			contentType: "application/json",
			defaultCapacity: 10,
			defaultWindow: 60000,
			capacityEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_REGISTER_CAPACITY",
			windowEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_REGISTER_WINDOW",
		}

		testRateLimit(t, ro)

		void t.test("endpoint availability", (t) => {
			void t.test("returns 404 when dynamic client registration is not enabled", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/oauth/register", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/json",
					},
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 404)
			})
		})

		void t.test("registration response", (t) => {
			void t.test("returns client_id", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_CLIENT_ID: "xxx",
					DOCSPACE_OAUTH_CLIENT_SECRET: "yyy",
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, "/oauth/register", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/json",
					},
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 201)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					client_id: "xxx",
				}

				assert.deepEqual(ab.v, eb)
			})

			void t.test("echoes request body", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_CLIENT_ID: "xxx",
					DOCSPACE_OAUTH_CLIENT_SECRET: "yyy",
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, "/oauth/register", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let ob: object = {
					test: "test",
				}

				let sb = r.safeSync(JSON.stringify, ob, null, 2)
				assert.ok(sb.err === undefined)

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/json",
					},
					body: sb.v,
				}

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 201)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					test: "test",
				}

				assert.partialDeepStrictEqual(ab.v, eb)
			})
		})
	})

	void t.test("/oauth/revoke", (t) => {
		let ot = ""
		let wt = ""

		t.before(async(t) => {
			let [hs, ha] = await setupHttp(t)

			let hp = onRequest(t, hs, async(_, res) => {
				ot = await sendAccessToken(_, res)
			})

			let tf = async(): Promise<void> => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
				}

				let a = await setup(t, e)

				wt = await requestAccessToken(a)
			}

			await Promise.race([hp, tf()])
		})

		let co: TestCorsOptions = {
			env: {},
			method: "POST",
			path: "/oauth/revoke",
		}

		testCors(t, co)

		let mo: TestMethodNotAllowedOptions = {
			env: {},
			path: "/oauth/revoke",
			allowed: "POST",
		}

		testMethodNotAllowed(t, mo)

		let to: TestUnsupportedMediaTypeOptions = {
			env: {},
			method: "POST",
			path: "/oauth/revoke",
		}

		testUnsupportedMediaType(t, to)

		let ro: TestRateLimitOptions = {
			env: {},
			method: "POST",
			path: "/oauth/revoke",
			contentType: "application/x-www-form-urlencoded",
			defaultCapacity: 10,
			defaultWindow: 60000,
			capacityEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_REVOKE_CAPACITY",
			windowEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_REVOKE_WINDOW",
		}

		testRateLimit(t, ro)

		let aeo: TestClientAuthErrorHandlingOptions = {
			path: "/oauth/revoke",
		}

		testClientAuthErrorHandling(t, aeo)

		let ao: TestClientAuthOptions = {
			skipCredentials: false,
			path: "/oauth/revoke",
			body: {
				token: "vvv",
			},
		}

		testClientAuth(t, ao)

		let uo: TestUserAgentOptions = {
			path: "/oauth/revoke",
			body: {
				token: "vvv",
			},
		}

		testUserAgent(t, uo)

		let ho: TestProxyHeaderForwardingOptions = {
			path: "/oauth/revoke",
			body: {
				token: "vvv",
			},
		}

		testProxyHeaderForwarding(t, ho)

		let eo: TestProxyErrorHandlingOptions = {
			path: "/oauth/revoke",
			body: {
				token: "vvv",
			},
		}

		testProxyErrorHandling(t, eo)

		void t.test("error handling", (t) => {
			void t.test("returns error when token parameter is missing", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: "http://localhost:8020/",
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, "/oauth/revoke", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "Parsing body\n" +
						"\t\ttoken: invalid_type Invalid input: expected string, received undefined",
				}

				assert.deepEqual(ab.v, eb)
			})

			void t.test("returns error when upstream is unreachable", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: "http://localhost:8020/",
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, "/oauth/revoke", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				f.set("token", "vvv")

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 500)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let d = "Revoking token\n" +
					"\tMaking bare request\n" +
					"\t\tMaking native request\n" +
					"\t\t\tfetch failed\n" +
					"\t\t\t\t" // there will be a platform-specific fetch error

				assert.ok(ab.v && typeof ab.v === "object")
				assert.deepEqual(Object.keys(ab.v), ["error", "error_description"])
				assert.ok("error" in ab.v && typeof ab.v.error === "string")
				assert.ok(ab.v.error === "server_error")
				assert.ok("error_description" in ab.v && typeof ab.v.error_description === "string")
				assert.ok(ab.v.error_description.startsWith(d))
			})
		})

		void t.test("token handling", (t) => {
			let requestRevocation = async(a: net.AddressInfo, f: URLSearchParams): Promise<void> => {
				let u = r.safeNew(URL, "/oauth/revoke", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 200)
			}

			void t.test("unwraps and forwards original token to upstream", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn<AsyncRequestListener>(async(req, res) => {
					let ab = await readHttpForm(req)
					assert.ok(ab.err === undefined)

					let eb: object = {
						token: ot,
					}

					assert.partialDeepStrictEqual(ab.v, eb)

					res.end()
				})

				let hp = onRequest(t, hs, hl)

				let hf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let f = new URLSearchParams()

					f.set("token", wt)

					await requestRevocation(a, f)
				}

				await Promise.race([hp, hf()])

				assert.ok(hl.mock.callCount() === 1)
			})

			void t.test("forwards non-wrapped token as-is to upstream", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn<AsyncRequestListener>(async(req, res) => {
					let ab = await readHttpForm(req)
					assert.ok(ab.err === undefined)

					let eb: object = {
						token: "vvv",
					}

					assert.partialDeepStrictEqual(ab.v, eb)

					res.end()
				})

				let hp = onRequest(t, hs, hl)

				let hf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let f = new URLSearchParams()

					f.set("token", "vvv")

					await requestRevocation(a, f)
				}

				await Promise.race([hp, hf()])

				assert.ok(hl.mock.callCount() === 1)
			})

			let ta: string[] = [
				"access_token",
				"refresh_token",
			]

			for (let tt of ta) {
				// eslint-disable-next-line typescript/no-loop-func
				void t.test(`forwards token_type_hint ${tt} when provided`, async(t) => {
					let [hs, ha] = await setupHttp(t)

					let hl = test.mock.fn<AsyncRequestListener>(async(req, res) => {
						let ab = await readHttpForm(req)
						assert.ok(ab.err === undefined)

						let eb: object = {
							token_type_hint: tt,
						}

						assert.partialDeepStrictEqual(ab.v, eb)

						res.end()
					})

					let hp = onRequest(t, hs, hl)

					let hf = async(): Promise<void> => {
						let e: object = {
							DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
						}

						let a = await setup(t, e)

						let f = new URLSearchParams()

						f.set("token", wt)
						f.set("token_type_hint", tt)

						await requestRevocation(a, f)
					}

					await Promise.race([hp, hf()])

					assert.ok(hl.mock.callCount() === 1)
				})
			}
		})
	})

	void t.test("/oauth/token", (t) => {
		let co: TestCorsOptions = {
			env: {},
			method: "POST",
			path: "/oauth/token",
		}

		testCors(t, co)

		let mo: TestMethodNotAllowedOptions = {
			env: {},
			path: "/oauth/token",
			allowed: "POST",
		}

		testMethodNotAllowed(t, mo)

		let to: TestUnsupportedMediaTypeOptions = {
			env: {},
			method: "POST",
			path: "/oauth/token",
		}

		testUnsupportedMediaType(t, to)

		let ro: TestRateLimitOptions = {
			env: {},
			method: "POST",
			path: "/oauth/token",
			contentType: "application/x-www-form-urlencoded",
			defaultCapacity: 10,
			defaultWindow: 60000,
			capacityEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_TOKEN_CAPACITY",
			windowEnv: "DOCSPACE_SERVER_RATE_LIMITS_OAUTH_TOKEN_WINDOW",
		}

		testRateLimit(t, ro)

		let aeo: TestClientAuthErrorHandlingOptions = {
			path: "/oauth/token",
		}

		testClientAuthErrorHandling(t, aeo)

		let ao: TestClientAuthOptions = {
			skipCredentials: false,
			path: "/oauth/token",
			body: {
				grant_type: "authorization_code",
				code: "vvv",
			},
		}

		testClientAuth(t, ao)

		let uo: TestUserAgentOptions = {
			path: "/oauth/token",
			body: {
				grant_type: "authorization_code",
				code: "vvv",
			},
		}

		testUserAgent(t, uo)

		let ho: TestProxyHeaderForwardingOptions = {
			path: "/oauth/token",
			body: {
				grant_type: "authorization_code",
				code: "vvv",
			},
		}

		testProxyHeaderForwarding(t, ho)

		let eo: TestProxyErrorHandlingOptions = {
			path: "/oauth/token",
			body: {
				grant_type: "authorization_code",
				code: "vvv",
			},
		}

		testProxyErrorHandling(t, eo)

		void t.test("error handling", (t) => {
			void t.test("returns error when grant_type is missing", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/oauth/token", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "Parsing body\n" +
						"\t\tinvalid_union: Invalid input",
				}

				assert.deepEqual(ab.v, eb)
			})

			void t.test("returns error when code is missing", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/oauth/token", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				f.set("grant_type", "authorization_code")

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "Parsing body\n" +
						"\t\tinvalid_union: Invalid input",
				}

				assert.deepEqual(ab.v, eb)
			})

			void t.test("returns error when refresh_token is missing", async(t) => {
				let a = await setup(t, {})

				let u = r.safeNew(URL, "/oauth/token", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				f.set("grant_type", "refresh_token")

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 400)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let eb: object = {
					error: "invalid_request",
					error_description: "Parsing body\n" +
						"\t\tinvalid_union: Invalid input",
				}

				assert.deepEqual(ab.v, eb)
			})

			void t.test("returns error when upstream is unreachable", async(t) => {
				let e: object = {
					DOCSPACE_OAUTH_BASE_URL: "http://localhost:8020/",
				}

				let a = await setup(t, e)

				let u = r.safeNew(URL, "/oauth/token", `http://[${a.address}]:${a.port}/`)
				assert.ok(u.err === undefined)

				let f = new URLSearchParams()

				f.set("grant_type", "authorization_code")
				f.set("code", "vvv")

				let i: RequestInit = {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded",
					},
					body: f.toString(),
				}

				let fetch = withAuth(globalThis.fetch)

				let res = await r.safeAsync(fetch, u.v, i)
				assert.ok(res.err === undefined)

				assert.ok(res.v.status === 500)

				let ab = await readFetchJson(res.v)
				assert.ok(ab.err === undefined)

				let d = "Requesting token\n" +
					"\tMaking request\n" +
					"\t\tMaking bare request\n" +
					"\t\t\tMaking native request\n" +
					"\t\t\t\tfetch failed\n" +
					"\t\t\t\t\t" // there will be a platform-specific fetch error

				assert.ok(ab.v && typeof ab.v === "object")
				assert.deepEqual(Object.keys(ab.v), ["error", "error_description"])
				assert.ok("error" in ab.v && typeof ab.v.error === "string")
				assert.ok(ab.v.error === "server_error")
				assert.ok("error_description" in ab.v && typeof ab.v.error_description === "string")
				assert.ok(ab.v.error_description.startsWith(d))
			})

			void t.test("returns error when upstream returns invalid token type", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					let b: object = {
						access_token: "invalid",
						token_type: "test",
					}

					let s = await sendJson(res, 200, b)
					assert.ok(s.err === undefined)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let u = r.safeNew(URL, "/oauth/token", `http://[${a.address}]:${a.port}/`)
					assert.ok(u.err === undefined)

					let f = new URLSearchParams()

					f.set("grant_type", "authorization_code")
					f.set("code", "vvv")

					let i: RequestInit = {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
						},
						body: f.toString(),
					}

					let fetch = withAuth(globalThis.fetch)

					let res = await r.safeAsync(fetch, u.v, i)
					assert.ok(res.err === undefined)

					assert.ok(res.v.status === 500)

					let ab = await readFetchJson(res.v)
					assert.ok(ab.err === undefined)

					let eb: object = {
						error: "server_error",
						error_description: "Encoding token\n" +
							"\tInvalid token",
					}

					assert.deepEqual(ab.v, eb)
				}

				await Promise.race([hp, tf()])
			})
		})

		void t.test("upstream request parameters", (t) => {
			void t.test("forwards authorization code grant to upstream", async(t) => {
				let sa: net.AddressInfo | undefined

				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn<AsyncRequestListener>(async(req, res) => {
					assert.ok(sa)

					let ab = await readHttpForm(req)
					assert.ok(ab.err === undefined)

					let eb: object = {
						grant_type: "authorization_code",
						code: "vvv",
						redirect_uri: `http://[${sa.address}]:${sa.port}/oauth/callback`,
					}

					assert.partialDeepStrictEqual(ab.v, eb)

					res.end()
				})

				let hp = onRequest(t, hs, hl)

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					sa = await setup(t, e)

					let u = r.safeNew(URL, "/oauth/token", `http://[${sa.address}]:${sa.port}/`)
					assert.ok(u.err === undefined)

					let f = new URLSearchParams()

					f.set("grant_type", "authorization_code")
					f.set("code", "vvv")

					let i: RequestInit = {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
						},
						body: f.toString(),
					}

					let fetch = withAuth(globalThis.fetch)

					let res = await r.safeAsync(fetch, u.v, i)
					assert.ok(res.err === undefined)
				}

				await Promise.race([hp, tf()])

				assert.ok(hl.mock.callCount() === 1)
			})

			void t.test("forwards refresh token grant to upstream ", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hl = test.mock.fn<AsyncRequestListener>(async(req, res) => {
					let ab = await readHttpForm(req)
					assert.ok(ab.err === undefined)

					let eb: object = {
						grant_type: "refresh_token",
						refresh_token: "zzz",
					}

					assert.partialDeepStrictEqual(ab.v, eb)

					res.end()
				})

				let hp = onRequest(t, hs, hl)

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let u = r.safeNew(URL, "/oauth/token", `http://[${a.address}]:${a.port}/`)
					assert.ok(u.err === undefined)

					let f = new URLSearchParams()

					f.set("grant_type", "refresh_token")
					f.set("refresh_token", "zzz")
					f.set("scope", "test")

					let i: RequestInit = {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
						},
						body: f.toString(),
					}

					let fetch = withAuth(globalThis.fetch)

					let res = await r.safeAsync(fetch, u.v, i)
					assert.ok(res.err === undefined)
				}

				await Promise.race([hp, tf()])

				assert.ok(hl.mock.callCount() === 1)
			})
		})

		void t.test("auth token signature algorithm", (t) => {
			void t.test("signs auth token with HS256 algorithm by default", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					await sendAccessToken(_, res)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
						DOCSPACE_OAUTH_AUTH_TOKEN_SECRET_KEY: "zzz",
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					checkJwtAlg(s, "HS256", "zzz")
				}

				await Promise.race([hp, tf()])
			})

			let ta: jwt.Algorithm[] = [
				"HS256",
				"HS384",
				"HS512",
			]

			for (let tt of ta) {
				void t.test(`signs auth token with ${tt} algorithm`, async(t) => {
					let [hs, ha] = await setupHttp(t)

					let hp = onRequest(t, hs, async(_, res) => {
						await sendAccessToken(_, res)
					})

					let tf = async(): Promise<void> => {
						let e: object = {
							DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
							DOCSPACE_OAUTH_AUTH_TOKEN_ALGORITHM: tt,
							DOCSPACE_OAUTH_AUTH_TOKEN_SECRET_KEY: "zzz",
						}

						let a = await setup(t, e)

						let s = await requestAccessToken(a)

						checkJwtAlg(s, tt, "zzz")
					}

					await Promise.race([hp, tf()])
				})
			}

			void t.test("signs auth token without signature when algorithm is disabled", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					await sendAccessToken(_, res)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
						DOCSPACE_OAUTH_AUTH_TOKEN_ALGORITHM: "",
						DOCSPACE_OAUTH_AUTH_TOKEN_SECRET_KEY: "",
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					checkJwtAlg(s, "none", "")
				}

				await Promise.race([hp, tf()])
			})
		})

		void t.test("auth token expiration time", (t) => {
			void t.test("sets default auth token expiration", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					await sendAccessToken(_, res)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					checkJwtTtl(s, 3600000)
				}

				await Promise.race([hp, tf()])
			})

			void t.test("sets custom auth token expiration", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					await sendAccessToken(_, res)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
						DOCSPACE_OAUTH_AUTH_TOKEN_TTL: 1800000,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					checkJwtTtl(s, 1800000)
				}

				await Promise.race([hp, tf()])
			})

			void t.test("creates auth token without expiration when ttl is disabled", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					await sendAccessToken(_, res)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
						DOCSPACE_OAUTH_AUTH_TOKEN_TTL: 0,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					checkJwtTtl(s, 0)
				}

				await Promise.race([hp, tf()])
			})

			let va: number[] = [3600000, 0]

			for (let expiresIn of va) {
				for (let ttl of va) {
					let m = 0

					let a: number[] = []

					if (expiresIn) {
						a.push(expiresIn)
					}

					if (ttl) {
						a.push(ttl)
					}

					if (a.length !== 0) {
						m = Math.min(...a)
					}

					void t.test(`expiresIn=${expiresIn} ttl=${ttl}`, async(t) => {
						let [hs, ha] = await setupHttp(t)

						let hp = onRequest(t, hs, async(_, res) => {
							let so: jwt.SignOptions = {
								algorithm: "none",
							}

							if (expiresIn) {
								so.expiresIn = expiresIn / 1000
							}

							let t = r.safeSync(jwt.sign, {}, "", so)
							assert.ok(t.err === undefined)

							let b: Record<string, unknown> = {
								access_token: t.v,
								token_type: "test",
							}

							let s = await sendJson(res, 200, b)
							assert.ok(s.err === undefined)
						})

						let tf = async(): Promise<void> => {
							let e: object = {
								DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
								DOCSPACE_OAUTH_AUTH_TOKEN_TTL: ttl,
							}

							let a = await setup(t, e)

							let s = await requestAccessToken(a)

							checkJwtTtl(s, m)
						}

						await Promise.race([hp, tf()])
					})
				}
			}

			void t.test("sets auth token expiration to current time when upstream is expired", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					let now = Date.now()

					let p: jwt.JwtPayload = {
						exp: Math.floor((now - 3600000) / 1000),
					}

					let so: jwt.SignOptions = {
						algorithm: "none",
					}

					let t = r.safeSync(jwt.sign, p, "", so)
					assert.ok(t.err === undefined)

					let b: object = {
						access_token: t.v,
						token_type: "test",
					}

					let s = await sendJson(res, 200, b)
					assert.ok(s.err === undefined)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					let o: jwt.DecodeOptions = {
						complete: true,
					}

					let decode = jwt.decode as (t: string, o: jwt.DecodeOptions) => jwt.Jwt | null

					let j = decode(s, o)
					assert.ok(j)

					assert.ok(typeof j.payload === "object")

					let now = Date.now()

					assert.ok(j.payload.exp && inDelta(j.payload.exp * 1000, now, 3000))
					assert.ok(j.payload.nbf && inDelta(j.payload.nbf * 1000, now, 3000))
					assert.ok(j.payload.iat && inDelta(j.payload.iat * 1000, now, 3000))
				}

				await Promise.race([hp, tf()])
			})
		})

		void t.test("auth token not-before time", (t) => {
			void t.test("sets auth token not-before to current time by default", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					await sendAccessToken(_, res)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					let o: jwt.DecodeOptions = {
						complete: true,
					}

					let decode = jwt.decode as (t: string, o: jwt.DecodeOptions) => jwt.Jwt | null

					let j = decode(s, o)
					assert.ok(j)

					assert.ok(typeof j.payload === "object")

					let now = Date.now()

					assert.ok(j.payload.nbf && inDelta(j.payload.nbf * 1000, now, 3000))
					assert.ok(j.payload.iat && inDelta(j.payload.iat * 1000, now, 3000))
				}

				await Promise.race([hp, tf()])
			})

			void t.test("respects future not-before from upstream", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					let now = Date.now()

					let p: jwt.JwtPayload = {
						nbf: Math.floor((now + 3600000) / 1000),
					}

					let o: jwt.SignOptions = {
						algorithm: "none",
					}

					let t = r.safeSync(jwt.sign, p, "", o)
					assert.ok(t.err === undefined)

					let b: object = {
						access_token: t.v,
						token_type: "test",
					}

					let s = await sendJson(res, 200, b)
					assert.ok(s.err === undefined)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					let o: jwt.DecodeOptions = {
						complete: true,
					}

					let decode = jwt.decode as (t: string, o: jwt.DecodeOptions) => jwt.Jwt | null

					let j = decode(s, o)
					assert.ok(j)

					assert.ok(typeof j.payload === "object")

					let now = Date.now()

					assert.ok(j.payload.nbf && inDelta(j.payload.nbf * 1000, now + 3600000, 3000))
					assert.ok(j.payload.iat && inDelta(j.payload.iat * 1000, now, 3000))
				}

				await Promise.race([hp, tf()])
			})

			void t.test("resets auth token not-before when it exceeds expiration", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					let now = Date.now()

					let p: jwt.JwtPayload = {
						nbf: Math.floor((now + 7200000) / 1000),
					}

					let o: jwt.SignOptions = {
						algorithm: "none",
					}

					let t = r.safeSync(jwt.sign, p, "", o)
					assert.ok(t.err === undefined)

					let b: object = {
						access_token: t.v,
						token_type: "test",
					}

					let s = await sendJson(res, 200, b)
					assert.ok(s.err === undefined)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
						DOCSPACE_OAUTH_AUTH_TOKEN_TTL: 3600000,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					let o: jwt.DecodeOptions = {
						complete: true,
					}

					let decode = jwt.decode as (t: string, o: jwt.DecodeOptions) => jwt.Jwt | null

					let j = decode(s, o)
					assert.ok(j)

					assert.ok(typeof j.payload === "object")

					let now = Date.now()

					assert.ok(j.payload.nbf && inDelta(j.payload.nbf * 1000, now, 3000))
					assert.ok(j.payload.iat && inDelta(j.payload.iat * 1000, now, 3000))
					assert.ok(j.payload.exp && inDelta(j.payload.exp * 1000, now + 3600000, 3000))
				}

				await Promise.race([hp, tf()])
			})

			void t.test("does not modify auth token not-before when upstream not-before is in the past", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					let now = Date.now()

					let p: jwt.JwtPayload = {
						nbf: Math.floor((now - 3600000) / 1000),
					}

					let o: jwt.SignOptions = {
						algorithm: "none",
					}

					let t = r.safeSync(jwt.sign, p, "", o)
					assert.ok(t.err === undefined)

					let b: object = {
						access_token: t.v,
						token_type: "test",
					}

					let s = await sendJson(res, 200, b)
					assert.ok(s.err === undefined)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					let o: jwt.DecodeOptions = {
						complete: true,
					}

					let decode = jwt.decode as (t: string, o: jwt.DecodeOptions) => jwt.Jwt | null

					let j = decode(s, o)
					assert.ok(j)

					assert.ok(typeof j.payload === "object")

					let now = Date.now()

					assert.ok(j.payload.nbf && inDelta(j.payload.nbf * 1000, now, 3000))
					assert.ok(j.payload.iat && inDelta(j.payload.iat * 1000, now, 3000))
				}

				await Promise.race([hp, tf()])
			})
		})

		void t.test("auth token payload", (t) => {
			void t.test("embeds upstream token in auth token payload", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hj: jwt.Jwt | null | undefined

				let hp = onRequest(t, hs, async(_, res) => {
					let so: jwt.SignOptions = {
						algorithm: "HS256",
						expiresIn: 3600000 / 1000,
					}

					let t = r.safeSync(jwt.sign, {}, "qqq", so)
					assert.ok(t.err === undefined)

					let co: jwt.DecodeOptions = {
						complete: true,
					}

					let decode = jwt.decode as (t: string, o: jwt.DecodeOptions) => jwt.Jwt | null

					hj = decode(t.v, co)
					assert.ok(hj)

					let b: object = {
						access_token: t.v,
						token_type: "test",
					}

					let s = await sendJson(res, 200, b)
					assert.ok(s.err === undefined)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let s = await requestAccessToken(a)

					assert.ok(hj)

					let o: jwt.DecodeOptions = {
						complete: true,
					}

					let decode = jwt.decode as (t: string, o: jwt.DecodeOptions) => jwt.Jwt | null

					let j = decode(s, o)
					assert.ok(j)

					assert.ok(typeof j.payload === "object")

					assert.deepEqual(j.payload.hdr, hj.header)
					assert.deepEqual(j.payload.pld, hj.payload)
					assert.deepEqual(j.payload.sgn, hj.signature)
				}

				await Promise.race([hp, tf()])
			})
		})

		void t.test("token response", (t) => {
			void t.test("returns token_type from upstream", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					let o: jwt.SignOptions = {
						algorithm: "none",
					}

					let t = r.safeSync(jwt.sign, {}, "", o)
					assert.ok(t.err === undefined)

					let b: object = {
						access_token: t.v,
						token_type: "test",
					}

					let s = await sendJson(res, 200, b)
					assert.ok(s.err === undefined)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let u = r.safeNew(URL, "/oauth/token", `http://[${a.address}]:${a.port}/`)
					assert.ok(u.err === undefined)

					let f = new URLSearchParams()

					f.set("grant_type", "authorization_code")
					f.set("code", "vvv")

					let i: RequestInit = {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
						},
						body: f.toString(),
					}

					let fetch = withAuth(globalThis.fetch)

					let res = await r.safeAsync(fetch, u.v, i)
					assert.ok(res.err === undefined)

					assert.ok(res.v.status === 200)

					let ab = await readFetchJson(res.v)
					assert.ok(ab.err === undefined)

					let eb: object = {
						token_type: "test",
					}

					assert.partialDeepStrictEqual(ab.v, eb)
				}

				await Promise.race([hp, tf()])
			})

			void t.test("returns refresh_token from upstream", async(t) => {
				let [hs, ha] = await setupHttp(t)

				let hp = onRequest(t, hs, async(_, res) => {
					let o: jwt.SignOptions = {
						algorithm: "none",
					}

					let t = r.safeSync(jwt.sign, {}, "", o)
					assert.ok(t.err === undefined)

					let b: object = {
						access_token: t.v,
						token_type: "test",
						refresh_token: "www",
					}

					let s = await sendJson(res, 200, b)
					assert.ok(s.err === undefined)
				})

				let tf = async(): Promise<void> => {
					let e: object = {
						DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
					}

					let a = await setup(t, e)

					let u = r.safeNew(URL, "/oauth/token", `http://[${a.address}]:${a.port}/`)
					assert.ok(u.err === undefined)

					let f = new URLSearchParams()

					f.set("grant_type", "refresh_token")
					f.set("refresh_token", "zzz")

					let i: RequestInit = {
						method: "POST",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
						},
						body: f.toString(),
					}

					let fetch = withAuth(globalThis.fetch)

					let res = await r.safeAsync(fetch, u.v, i)
					assert.ok(res.err === undefined)

					assert.ok(res.v.status === 200)

					let ab = await readFetchJson(res.v)
					assert.ok(ab.err === undefined)

					let eb: object = {
						refresh_token: "www",
					}

					assert.partialDeepStrictEqual(ab.v, eb)
				}

				await Promise.race([hp, tf()])
			})

			let va = [3600000, 1800000, 0]

			for (let expiresIn of va) {
				for (let expires_in of va) {
					for (let ttl of va) {
						let m = 0

						let a: number[] = []

						if (expiresIn) {
							a.push(expiresIn)
						}

						if (expires_in) {
							a.push(expires_in)
						}

						if (ttl) {
							a.push(ttl)
						}

						if (a.length !== 0) {
							m = Math.min(...a)
						}

						void t.test(`expiresIn=${expiresIn} expires_in=${expires_in} ttl=${ttl}`, async(t) => {
							let [hs, ha] = await setupHttp(t)

							let hp = onRequest(t, hs, async(_, res) => {
								let so: jwt.SignOptions = {
									algorithm: "none",
								}

								if (expiresIn) {
									so.expiresIn = expiresIn / 1000
								}

								let t = r.safeSync(jwt.sign, {}, "", so)
								assert.ok(t.err === undefined)

								let b: Record<string, unknown> = {
									access_token: t.v,
									token_type: "test",
								}

								if (expires_in) {
									b.expires_in = expires_in / 1000
								}

								let s = await sendJson(res, 200, b)
								assert.ok(s.err === undefined)
							})

							let tf = async(): Promise<void> => {
								let e: object = {
									DOCSPACE_OAUTH_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
									DOCSPACE_OAUTH_AUTH_TOKEN_TTL: ttl,
								}

								let a = await setup(t, e)

								let u = r.safeNew(URL, "/oauth/token", `http://[${a.address}]:${a.port}/`)
								assert.ok(u.err === undefined)

								let f = new URLSearchParams()

								f.set("grant_type", "authorization_code")
								f.set("code", "vvv")

								let i: RequestInit = {
									method: "POST",
									headers: {
										"Content-Type": "application/x-www-form-urlencoded",
									},
									body: f.toString(),
								}

								let fetch = withAuth(globalThis.fetch)

								let res = await r.safeAsync(fetch, u.v, i)
								assert.ok(res.err === undefined)

								assert.ok(res.v.status === 200)

								let b = await readFetchJson(res.v)
								assert.ok(b.err === undefined)

								assert.ok(b.v)
								assert.ok(typeof b.v === "object")

								if (m) {
									assert.ok("expires_in" in b.v && typeof b.v.expires_in === "number")
									assert.ok(inDelta(b.v.expires_in, m / 1000, 3000))
								} else {
									assert.ok(!("expires_in" in b.v))
								}
							}

							await Promise.race([hp, tf()])
						})
					}
				}
			}
		})
	})
})
