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
import type * as z from "zod"
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
