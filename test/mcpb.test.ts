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
  const rf: (p: string, e: "utf8") => Promise<string> = fs.readFile

  const f = await r.safeAsync(rf, "./mcpb/manifest.json", "utf8")
  if (f.err) {
    return r.error(new Error("Reading file", {cause: f.err}))
  }

  const j = r.safeSync(JSON.parse, f.v)
  if (j.err) {
    return r.error(new Error("Parsing json", {cause: j.err}))
  }

  const s = dist.ManifestSchema.safeParse(j.v)
  if (s.error) {
    return r.error(new Error("Parsing schema", {cause: s.error}))
  }

  return r.ok(j.v)
}

void test.suite("mcpb manifest", () => {
  const readManifestOnce = once(readManifest)

  void test("validates against $schema", async() => {
    const m = await readManifestOnce()
    assert.ok(m.err === undefined)

    const a = new ajv.Ajv()
    ajvFormats.default(a)

    const rf: (p: string, e: "utf8") => Promise<string> = fs.readFile

    const s = await r.safeAsync(rf, m.v.$schema, "utf8")
    assert.ok(s.err === undefined)

    const o = r.safeSync(JSON.parse, s.v)
    assert.ok(o.err === undefined)

    const v = r.safeSync(a.compile.bind(a), o.v)
    assert.ok(v.err === undefined)

    assert.ok(v.v(m.v))
  })

  void test("matches server metadata", async(t) => {
    const m = await readManifestOnce()
    assert.ok(m.err === undefined)

    const so: SetupMcpOptions = {
      transport: "stdio",
      host: "",
      port: 0,
      env: {},
    }

    const c = await setupMcp(t, so)

    const i = c.getServerVersion()
    assert.ok(i !== undefined)

    assert.ok(m.v.version === i.version)
  })

  void test("declares all config options", async() => {
    const m = await readManifestOnce()
    assert.ok(m.err === undefined)

    const o: Record<string, dist.ManifestOption> = {}

    for (const i of Object.values(spec)) {
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
    const m = await readManifestOnce()
    assert.ok(m.err === undefined)

    const o: Record<string, string> = {}

    for (const i of Object.values(spec)) {
      if (i.distributions.includes("mcpb")) {
        o[`${config.envPrefix}${i.env}`] =
          `\${user_config.${`${config.envPrefix}${i.env}`.toLowerCase()}}`
      }
    }

    assert.deepEqual(m.v.server.mcp_config.env, o)
  })

  void test("matches server tools", async(t) => {
    const m = await readManifestOnce()
    assert.ok(m.err === undefined)

    const so: SetupMcpOptions = {
      transport: "stdio",
      host: "",
      port: 0,
      env: {},
    }

    const c = await setupMcp(t, so)

    const req: types.ListToolsRequest = {
      method: "tools/list",
      params: {},
    }

    const res = await r.safeAsync(c.request.bind(c), req, types.ListToolsResultSchema)
    assert.ok(res.err === undefined)

    for (const d of res.v.tools) {
      assert.ok(d.description)

      let a: dist.ManifestTool | undefined

      for (const t of m.v.tools) {
        if (t.name === d.name) {
          a = t
          break
        }
      }

      assert.ok(a !== undefined)

      const e: dist.ManifestTool = {
        name: d.name,
        description: d.description,
      }

      assert.deepEqual(a, e)
    }

    assert.ok(m.v.tools.length === res.v.tools.length)
  })
})
