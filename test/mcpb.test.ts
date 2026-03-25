/**
 * @module test
 */

import assert from "node:assert/strict"
import fs from "node:fs/promises"
import test from "node:test"
import * as types from "@modelcontextprotocol/sdk/types.js"
import ajv from "ajv"
import ajvFormats from "ajv-formats"
import * as spec from "../lib/config/spec.ts"
import * as config from "../lib/config.ts"
import * as dist from "../lib/dist.ts"
import * as r from "../lib/util/result.ts"
import type {SetupMcpOptions} from "./util.ts"
import {once, setupMcp} from "./util.ts"

async function readManifest(): Promise<r.Result<dist.Manifest, Error>> {
	let rf: (p: string, e: "utf8") => Promise<string> = fs.readFile

	let f = await r.safeAsync(rf, "./mcpb/manifest.json", "utf8")
	if (f.err) {
		return r.error(new Error("Reading file", {cause: f.err}))
	}

	let j = r.safeSync(JSON.parse, f.v)
	if (j.err) {
		return r.error(new Error("Parsing json", {cause: j.err}))
	}

	let s = dist.ManifestSchema.safeParse(j.v)
	if (s.error) {
		return r.error(new Error("Parsing schema", {cause: s.error}))
	}

	return r.ok(j.v)
}

void test.suite("mcpb manifest", () => {
	let readManifestOnce = once(readManifest)

	void test("validates against $schema", async() => {
		let m = await readManifestOnce()
		assert.ok(m.err === undefined)

		let a = new ajv.Ajv()
		ajvFormats.default(a)

		let rf: (p: string, e: "utf8") => Promise<string> = fs.readFile

		let s = await r.safeAsync(rf, m.v.$schema, "utf8")
		assert.ok(s.err === undefined)

		let o = r.safeSync(JSON.parse, s.v)
		assert.ok(o.err === undefined)

		let v = r.safeSync(a.compile.bind(a), o.v)
		assert.ok(v.err === undefined)

		assert.ok(v.v(m.v))
	})

	void test("matches server metadata", async(t) => {
		let m = await readManifestOnce()
		assert.ok(m.err === undefined)

		let so: SetupMcpOptions = {
			transport: "stdio",
			host: "",
			port: 0,
			env: {},
		}

		let c = await setupMcp(t, so)

		let i = c.getServerVersion()
		assert.ok(i !== undefined)

		assert.ok(m.v.version === i.version)
	})

	void test("declares all config options", async() => {
		let m = await readManifestOnce()
		assert.ok(m.err === undefined)

		let o: Record<string, dist.ManifestOption> = {}

		for (let i of Object.values(spec)) {
			if (i.distributions.includes("mcpb")) {
				o[`${config.envPrefix}${i.env}`.toLowerCase()] = {
					type: i.type,
					title: i.title,
					description: i.description,
					required: false,
					default: i.default,
				}
			}
		}

		assert.deepEqual(m.v.user_config, o)
	})

	void test("maps all config options", async() => {
		let m = await readManifestOnce()
		assert.ok(m.err === undefined)

		let o: Record<string, string> = {}

		for (let i of Object.values(spec)) {
			if (i.distributions.includes("mcpb")) {
				o[`${config.envPrefix}${i.env}`] =
					`\${user_config.${`${config.envPrefix}${i.env}`.toLowerCase()}}`
			}
		}

		assert.deepEqual(m.v.server.mcp_config.env, o)
	})

	void test("matches server tools", async(t) => {
		let m = await readManifestOnce()
		assert.ok(m.err === undefined)

		let so: SetupMcpOptions = {
			transport: "stdio",
			host: "",
			port: 0,
			env: {},
		}

		let c = await setupMcp(t, so)

		let req: types.ListToolsRequest = {
			method: "tools/list",
			params: {},
		}

		let res = await r.safeAsync(c.request.bind(c), req, types.ListToolsResultSchema)
		assert.ok(res.err === undefined)

		for (let d of res.v.tools) {
			assert.ok(d.description)

			let a: dist.ManifestTool | undefined

			for (let t of m.v.tools) {
				if (t.name === d.name) {
					a = t
					break
				}
			}

			assert.ok(a !== undefined)

			let e: dist.ManifestTool = {
				name: d.name,
				description: d.description,
			}

			assert.deepEqual(a, e)
		}

		assert.ok(m.v.tools.length === res.v.tools.length)
	})
})
