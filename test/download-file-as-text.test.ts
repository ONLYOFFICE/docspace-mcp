/**
 * @module
 */

import assert from "node:assert/strict"
import test from "node:test"
import type * as types from "@modelcontextprotocol/sdk/types.js"
import * as r from "../lib/util/result.ts"
import type {AsyncRequestListener, SetupMcpOptions} from "./util.ts"
import {onRequest, readHttpData, sendJson, setupHttp, setupMcp} from "./util.ts"

type Route = {
  method: string
  path: string
  status: number
  json?: unknown
  text?: string
}

type Served = {
  method: string
  url: URL
}

async function callTool(t: test.TestContext, routes: (base: string) => Route[], args: Record<string, unknown>): Promise<[types.CallToolResult, Served[]]> {
  const [hs, ha] = await setupHttp(t)

  const base = `http://[${ha.address}]:${ha.port}/`
  const rs = routes(base)

  const served: Served[] = []

  const hl: AsyncRequestListener = async(req, res) => {
    assert.ok(req.url && req.method)

    const url = new URL(req.url, "http://localhost/")

    const d = await readHttpData(req)
    assert.ok(d.err === undefined)

    served.push({method: req.method, url})

    const rt = rs.find((x) => x.method === req.method && x.path === url.pathname)
    assert.ok(rt, `unexpected request ${req.method} ${url.pathname}`)

    if (rt.text !== undefined) {
      res.statusCode = rt.status
      res.setHeader("Content-Type", "application/octet-stream")
      res.end(rt.text)
      return
    }

    const sr = await sendJson(res, rt.status, rt.json)
    assert.ok(sr.err === undefined)
  }

  const hp = onRequest(t, hs, hl)

  const tf = async(): Promise<types.CallToolResult> => {
    const so: SetupMcpOptions = {
      transport: "stdio",
      host: "",
      port: 0,
      env: {
        DOCSPACE_BASE_URL: base,
        DOCSPACE_API_KEY: "xxx",
      },
    }

    const cl = await setupMcp(t, so)

    const cr = await r.safeAsync(cl.callTool.bind(cl), {name: "download_file_as_text", arguments: args})
    assert.ok(cr.err === undefined, String(cr.err))

    return cr.v as types.CallToolResult
  }

  const v = await Promise.race([hp.then(() => undefined), tf()])
  assert.ok(v)

  return [v, served]
}

function envelope(response: unknown): unknown {
  return {response, count: 1, links: [], status: 0, statusCode: 200}
}

function text(v: types.CallToolResult): string {
  const c = v.content[0]
  assert.ok(c.type === "text")
  return c.text
}

function fileInfo(ext: string): Route {
  return {method: "GET", path: "/api/2.0/files/file/5", status: 200, json: envelope({id: 5, title: `a${ext}`, fileExst: ext})}
}

const skill = "---\nname: brand-voice\ndescription: Writes in the brand voice.\n---\n\n# Brand voice\n\nUse short sentences.\n"

void test.suite("download_file_as_text", () => {
  void test("downloads a markdown file as it is", async(t) => {
    const [v, s] = await callTool(t, () => [
      fileInfo(".md"),
      {method: "GET", path: "/filehandler.ashx", status: 200, text: skill},
    ], {fileId: 5})

    assert.ok(!v.isError, text(v))
    assert.equal(text(v), skill)

    const d = s.find((x) => x.url.pathname === "/filehandler.ashx")
    assert.ok(d)
    assert.equal(d.url.searchParams.get("action"), "download")
    assert.equal(d.url.searchParams.get("fileid"), "5")
    assert.ok(!s.some((x) => x.url.pathname.includes("bulkdownload")))
  })

  void test("matches the extension in any case", async(t) => {
    const [v] = await callTool(t, () => [
      fileInfo(".MD"),
      {method: "GET", path: "/filehandler.ashx", status: 200, text: skill},
    ], {fileId: 5})

    assert.ok(!v.isError, text(v))
    assert.equal(text(v), skill)
  })

  void test("does not take a json file for an error response", async(t) => {
    const c = "{\"error\": \"not an error\", \"success\": false, \"message\": \"just data\"}"

    const [v] = await callTool(t, () => [
      fileInfo(".json"),
      {method: "GET", path: "/filehandler.ashx", status: 200, text: c},
    ], {fileId: 5})

    assert.ok(!v.isError, text(v))
    assert.equal(text(v), c)
  })

  void test("truncates a plain text file", async(t) => {
    const [v] = await callTool(t, () => [
      fileInfo(".txt"),
      {method: "GET", path: "/filehandler.ashx", status: 200, text: "abcdefghij"},
    ], {fileId: 5, offset: 2, limit: 3})

    assert.ok(!v.isError, text(v))
    assert.ok(text(v).startsWith("cde\n\n[Truncated:"), text(v))
    assert.ok(text(v).includes("offset=5"), text(v))
  })

  void test("reports the message of the file handler", async(t) => {
    const [v] = await callTool(t, () => [
      fileInfo(".md"),
      {method: "GET", path: "/filehandler.ashx", status: 403, text: "You don't have enough permission to perform the operation"},
    ], {fileId: 5})

    assert.ok(v.isError)
    assert.ok(text(v).includes("403 You don't have enough permission to perform the operation"), text(v))
  })

  void test("converts a document to text", async(t) => {
    const [v, s] = await callTool(t, (base) => [
      fileInfo(".docx"),
      {method: "GET", path: "/api/2.0/files/settings", status: 200, json: envelope({extsConvertible: {".docx": [".pdf", ".txt"]}})},
      {method: "PUT", path: "/api/2.0/files/fileops/bulkdownload", status: 200, json: envelope([{id: "op", progress: 0, finished: false}])},
      {method: "GET", path: "/api/2.0/files/fileops", status: 200, json: envelope([{id: "op", progress: 100, finished: true, processed: "1", url: `${base}converted`}])},
      {method: "GET", path: "/converted", status: 200, text: "Converted text"},
    ], {fileId: 5})

    assert.ok(!v.isError, text(v))
    assert.equal(text(v), "Converted text")
    assert.ok(!s.some((x) => x.url.pathname === "/filehandler.ashx"))
  })
})
