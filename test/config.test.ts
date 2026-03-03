/**
 * @module test
 */

import assert from "node:assert/strict"
import test from "node:test"
import * as types from "@modelcontextprotocol/sdk/types.js"
import type * as z from "zod"
import * as r from "../lib/util/result.ts"
import type {SetupMcpOptions} from "./util.ts"
import {powerSet, setupMcp} from "./util.ts"

void test.suite("global config", () => {
	void test.suite("validates complex combinations", () => {
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
})
