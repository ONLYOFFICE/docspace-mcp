/**
 * @module test
 */

import assert from "node:assert/strict"
import fs from "node:fs/promises"
import path from "node:path"
import test from "node:test"
import * as mcp from "../lib/mcp.ts"
import * as r from "../lib/util/result.ts"
import type {SetupMcpOptions} from "./util.ts"
import {once, setupMcp} from "./util.ts"

type Plugin = Record<string, unknown> & {
  version: string
  extensions: {
    "com.openai": {
      interface: {
        composerIcon: string
        logo: string
      }
      review: {
        test_cases: {
          positive: {
            tools_triggered: string
          }[]
        }
      }
    }
  }
}

type ClaudePlugin = Record<string, unknown> & {
  icon: string
}

type Mcp = {
  mcpServers: Record<string, {
    url: string
  }>
}

async function readJson<T>(p: string): Promise<r.Result<T, Error>> {
  let rf: (p: string, e: "utf8") => Promise<string> = fs.readFile

  let f = await r.safeAsync(rf, p, "utf8")
  if (f.err) {
    return r.error(new Error("Reading file", {cause: f.err}))
  }

  let j = r.safeSync(JSON.parse, f.v)
  if (j.err) {
    return r.error(new Error("Parsing json", {cause: j.err}))
  }

  return r.ok(j.v as T)
}

function readPlugin(): Promise<r.Result<Plugin, Error>> {
  return readJson("./plugin/plugin.json")
}

function readMcp(): Promise<r.Result<Mcp, Error>> {
  return readJson("./plugin/mcp.json")
}

void test.suite("agent plugin", () => {
  let readPluginOnce = once(readPlugin)
  let readMcpOnce = once(readMcp)

  void test("reads plugin manifest", async() => {
    let p = await readPluginOnce()
    assert.ok(p.err === undefined, p.err)
  })

  void test("reads mcp config", async() => {
    let m = await readMcpOnce()
    assert.ok(m.err === undefined, m.err)
    assert.ok(Object.keys(m.v.mcpServers).length === 1)
  })

  void test("uses only server fields that the ChatGPT desktop app accepts", async() => {
    let m = await readMcpOnce()
    assert.ok(m.err === undefined)

    for (let s of Object.values(m.v.mcpServers)) {
      for (let k of Object.keys(s)) {
        assert.ok(["type", "url", "headers"].includes(k), k)
      }
    }
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

  void test("triggers existing tools in test cases", async() => {
    let p = await readPluginOnce()
    assert.ok(p.err === undefined)

    let n: string[] = []

    for (let s of mcp.regularToolsets) {
      for (let t of s.tools) {
        n.push(t.name)
      }
    }

    for (let c of p.v.extensions["com.openai"].review.test_cases.positive) {
      for (let t of c.tools_triggered.split(",")) {
        assert.ok(n.includes(t.trim()), t)
      }
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

function readClaudePlugin(): Promise<r.Result<ClaudePlugin, Error>> {
  return readJson("./plugin/.claude-plugin/plugin.json")
}

function readClaudeMcp(): Promise<r.Result<Mcp, Error>> {
  return readJson("./plugin/.mcp.json")
}

void test.suite("claude plugin", () => {
  let readPluginOnce = once(readPlugin)
  let readMcpOnce = once(readMcp)
  let readClaudePluginOnce = once(readClaudePlugin)
  let readClaudeMcpOnce = once(readClaudeMcp)

  void test("reads plugin manifest", async() => {
    let p = await readClaudePluginOnce()
    assert.ok(p.err === undefined, p.err)
  })

  void test("reads mcp config", async() => {
    let m = await readClaudeMcpOnce()
    assert.ok(m.err === undefined, m.err)
    assert.ok(Object.keys(m.v.mcpServers).length === 1)
  })

  void test("matches agent plugin", async() => {
    let p = await readPluginOnce()
    assert.ok(p.err === undefined)

    let m = await readMcpOnce()
    assert.ok(m.err === undefined)

    let cp = await readClaudePluginOnce()
    assert.ok(cp.err === undefined)

    let cm = await readClaudeMcpOnce()
    assert.ok(cm.err === undefined)

    for (let k of ["name", "version", "description", "author", "homepage", "repository", "license", "keywords"]) {
      assert.deepEqual(cp.v[k], p.v[k], k)
    }

    assert.ok(cp.v.icon === p.v.extensions["com.openai"].interface.logo)
    assert.deepEqual(Object.keys(cm.v.mcpServers), Object.keys(m.v.mcpServers))

    for (let [n, s] of Object.entries(m.v.mcpServers)) {
      let c = cm.v.mcpServers[n]
      assert.ok(c !== undefined, n)
      assert.ok(c.url === s.url, n)
    }
  })

  void test("includes referenced files", async() => {
    let p = await readClaudePluginOnce()
    assert.ok(p.err === undefined)

    let s = await r.safeAsync(fs.stat, path.join("./plugin/", p.v.icon))
    assert.ok(s.err === undefined, p.v.icon)
  })

  void test("includes license and readme", async() => {
    for (let f of ["LICENSE", "README.md"]) {
      let s = await r.safeAsync(fs.stat, path.join("./plugin/", f))
      assert.ok(s.err === undefined, f)
    }
  })

  void test("has no top-level bin directory", async() => {
    let s = await r.safeAsync(fs.stat, "./plugin/bin")
    assert.ok(s.err !== undefined)
  })

  void test("contains no secrets", async() => {
    let rf: (p: string, e: "utf8") => Promise<string> = fs.readFile

    for (let f of ["./plugin/.claude-plugin/plugin.json", "./plugin/.mcp.json"]) {
      let c = await r.safeAsync(rf, f, "utf8")
      assert.ok(c.err === undefined)

      for (let k of ["clientSecret", "headers", "headersHelper"]) {
        assert.ok(!c.v.includes(`"${k}"`), `${f}: ${k}`)
      }
    }
  })
})
