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
import net from "node:net"
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
