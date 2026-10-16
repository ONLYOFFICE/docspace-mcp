/**
 * @module test
 */

import assert from "node:assert/strict"
import fs from "node:fs/promises"
import path from "node:path"
import test from "node:test"
import type * as z from "zod"
import * as dist from "../lib/dist.ts"
import * as r from "../lib/util/result.ts"
import type {SetupMcpOptions} from "./util.ts"
import {once, setupMcp} from "./util.ts"

async function readJson<T>(p: string, s: z.ZodType<T>): Promise<r.Result<T, Error>> {
  let rf: (p: string, e: "utf8") => Promise<string> = fs.readFile

  let f = await r.safeAsync(rf, p, "utf8")
  if (f.err) {
    return r.error(new Error("Reading file", {cause: f.err}))
  }

  let j = r.safeSync(JSON.parse, f.v)
  if (j.err) {
    return r.error(new Error("Parsing json", {cause: j.err}))
  }

  let o = s.safeParse(j.v)
  if (o.error) {
    return r.error(new Error("Parsing schema", {cause: o.error}))
  }

  return r.ok(o.data)
}

function readPlugin(): Promise<r.Result<dist.Plugin, Error>> {
  return readJson("./plugin/plugin.json", dist.PluginSchema)
}

function readMcp(): Promise<r.Result<dist.PluginMcp, Error>> {
  return readJson("./plugin/mcp.json", dist.PluginMcpSchema)
}

void test.suite("openai plugin", () => {
  let readPluginOnce = once(readPlugin)
  let readMcpOnce = once(readMcp)

  void test("validates plugin manifest", async() => {
    let p = await readPluginOnce()
    assert.ok(p.err === undefined, p.err)
  })

  void test("validates mcp config", async() => {
    let m = await readMcpOnce()
    assert.ok(m.err === undefined, m.err)
    assert.ok(Object.keys(m.v.mcpServers).length === 1)
  })

  void test("matches server metadata", async(t) => {
    let p = await readPluginOnce()
    assert.ok(p.err === undefined)

    let so: SetupMcpOptions = {
      transport: "stdio",
      host: "",
      port: 0,
      env: {},
    }

    let c = await setupMcp(t, so)

    let i = c.getServerVersion()
    assert.ok(i !== undefined)

    assert.ok(p.v.version === i.version)
  })

  void test("includes referenced files", async() => {
    let p = await readPluginOnce()
    assert.ok(p.err === undefined)

    let o = p.v.extensions["com.openai"].interface

    for (let f of [o.composerIcon, o.logo]) {
      let s = await r.safeAsync(fs.stat, path.join("./plugin/", f))
      assert.ok(s.err === undefined, f)
      assert.ok(s.v.size <= 5 * 1024 * 1024, f)
    }
  })

  void test("contains no secrets", async() => {
    let rf: (p: string, e: "utf8") => Promise<string> = fs.readFile

    for (let f of ["./plugin/plugin.json", "./plugin/mcp.json"]) {
      let c = await r.safeAsync(rf, f, "utf8")
      assert.ok(c.err === undefined)

      for (let k of ["clientSecret", "test_credentials", "reviewer_instructions", "headers"]) {
        assert.ok(!c.v.includes(`"${k}"`), `${f}: ${k}`)
      }
    }
  })
})
