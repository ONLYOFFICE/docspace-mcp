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
  const rf: (p: string, e: "utf8") => Promise<string> = fs.readFile

  const f = await r.safeAsync(rf, p, "utf8")
  if (f.err) {
    return r.error(new Error("Reading file", {cause: f.err}))
  }

  const j = r.safeSync(JSON.parse, f.v)
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
  const readPluginOnce = once(readPlugin)
  const readMcpOnce = once(readMcp)

  void test("reads plugin manifest", async() => {
    const p = await readPluginOnce()
    assert.ok(p.err === undefined, p.err)
  })

  void test("reads mcp config", async() => {
    const m = await readMcpOnce()
    assert.ok(m.err === undefined, m.err)
    assert.ok(Object.keys(m.v.mcpServers).length === 1)
  })

  void test("uses only server fields that the ChatGPT desktop app accepts", async() => {
    const m = await readMcpOnce()
    assert.ok(m.err === undefined)

    for (const s of Object.values(m.v.mcpServers)) {
      for (const k of Object.keys(s)) {
        assert.ok(["type", "url", "headers"].includes(k), k)
      }
    }
  })

  void test("matches server metadata", async(t) => {
    const p = await readPluginOnce()
    assert.ok(p.err === undefined)

    const so: SetupMcpOptions = {
      transport: "stdio",
      host: "",
      port: 0,
      env: {},
    }

    const c = await setupMcp(t, so)

    const i = c.getServerVersion()
    assert.ok(i !== undefined)

    assert.ok(p.v.version === i.version)
  })

  void test("includes referenced files", async() => {
    const p = await readPluginOnce()
    assert.ok(p.err === undefined)

    const o = p.v.extensions["com.openai"].interface

    for (const f of [o.composerIcon, o.logo]) {
      const s = await r.safeAsync(fs.stat, path.join("./plugin/", f))
      assert.ok(s.err === undefined, f)
      assert.ok(s.v.size <= 5 * 1024 * 1024, f)
    }
  })

  void test("triggers existing tools in test cases", async() => {
    const p = await readPluginOnce()
    assert.ok(p.err === undefined)

    const n: string[] = []

    for (const s of mcp.regularToolsets) {
      for (const t of s.tools) {
        n.push(t.name)
      }
    }

    for (const c of p.v.extensions["com.openai"].review.test_cases.positive) {
      for (const t of c.tools_triggered.split(",")) {
        assert.ok(n.includes(t.trim()), t)
      }
    }
  })

  void test("contains no secrets", async() => {
    const rf: (p: string, e: "utf8") => Promise<string> = fs.readFile

    for (const f of ["./plugin/plugin.json", "./plugin/mcp.json"]) {
      const c = await r.safeAsync(rf, f, "utf8")
      assert.ok(c.err === undefined)

      for (const k of ["clientSecret", "test_credentials", "reviewer_instructions", "headers"]) {
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
  const readPluginOnce = once(readPlugin)
  const readMcpOnce = once(readMcp)
  const readClaudePluginOnce = once(readClaudePlugin)
  const readClaudeMcpOnce = once(readClaudeMcp)

  void test("reads plugin manifest", async() => {
    const p = await readClaudePluginOnce()
    assert.ok(p.err === undefined, p.err)
  })

  void test("reads mcp config", async() => {
    const m = await readClaudeMcpOnce()
    assert.ok(m.err === undefined, m.err)
    assert.ok(Object.keys(m.v.mcpServers).length === 1)
  })

  void test("matches agent plugin", async() => {
    const p = await readPluginOnce()
    assert.ok(p.err === undefined)

    const m = await readMcpOnce()
    assert.ok(m.err === undefined)

    const cp = await readClaudePluginOnce()
    assert.ok(cp.err === undefined)

    const cm = await readClaudeMcpOnce()
    assert.ok(cm.err === undefined)

    for (const k of ["name", "version", "description", "author", "homepage", "repository", "license", "keywords"]) {
      assert.deepEqual(cp.v[k], p.v[k], k)
    }

    assert.ok(cp.v.icon === p.v.extensions["com.openai"].interface.logo)
    assert.deepEqual(Object.keys(cm.v.mcpServers), Object.keys(m.v.mcpServers))

    for (const [n, s] of Object.entries(m.v.mcpServers)) {
      const c = cm.v.mcpServers[n]
      assert.ok(c !== undefined, n)
      assert.ok(c.url === s.url, n)
    }
  })

  void test("includes referenced files", async() => {
    const p = await readClaudePluginOnce()
    assert.ok(p.err === undefined)

    const s = await r.safeAsync(fs.stat, path.join("./plugin/", p.v.icon))
    assert.ok(s.err === undefined, p.v.icon)
  })

  void test("includes license and readme", async() => {
    for (const f of ["LICENSE", "README.md"]) {
      const s = await r.safeAsync(fs.stat, path.join("./plugin/", f))
      assert.ok(s.err === undefined, f)
    }
  })

  void test("has no top-level bin directory", async() => {
    const s = await r.safeAsync(fs.stat, "./plugin/bin")
    assert.ok(s.err !== undefined)
  })

  void test("contains no secrets", async() => {
    const rf: (p: string, e: "utf8") => Promise<string> = fs.readFile

    for (const f of ["./plugin/.claude-plugin/plugin.json", "./plugin/.mcp.json"]) {
      const c = await r.safeAsync(rf, f, "utf8")
      assert.ok(c.err === undefined)

      for (const k of ["clientSecret", "headers", "headersHelper"]) {
        assert.ok(!c.v.includes(`"${k}"`), `${f}: ${k}`)
      }
    }
  })
})
