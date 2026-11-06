/**
 * @module
 */

import assert from "node:assert/strict"
import test from "node:test"
import type * as types from "@modelcontextprotocol/sdk/types.js"
import type {MockRoute} from "./util.ts"
import {callMockedTool} from "./util.ts"

function envelope(response: unknown): unknown {
  return {response, count: 1, links: [], status: 0, statusCode: 200}
}

function text(v: types.CallToolResult): string {
  const c = v.content[0]
  assert.ok(c.type === "text")
  return c.text
}

function fileInfo(ext: string): MockRoute {
  return {method: "GET", path: "/api/2.0/files/file/5", status: 200, json: envelope({id: 5, title: `a${ext}`, fileExst: ext})}
}

const skill = "---\nname: brand-voice\ndescription: Writes in the brand voice.\n---\n\n# Brand voice\n\nUse short sentences.\n"

void test.suite("download_file_as_text", () => {
  void test("downloads a markdown file as it is", async(t) => {
    const [v, s] = await callMockedTool(t, () => [
      fileInfo(".md"),
      {method: "GET", path: "/filehandler.ashx", status: 200, text: skill},
    ], "download_file_as_text", {fileId: 5})

    assert.ok(!v.isError, text(v))
    assert.equal(text(v), skill)

    const d = s.find((x) => x.url.pathname === "/filehandler.ashx")
    assert.ok(d)
    assert.equal(d.url.searchParams.get("action"), "download")
    assert.equal(d.url.searchParams.get("fileid"), "5")
    assert.ok(!s.some((x) => x.url.pathname.includes("bulkdownload")))
  })

  void test("matches the extension in any case", async(t) => {
    const [v] = await callMockedTool(t, () => [
      fileInfo(".MD"),
      {method: "GET", path: "/filehandler.ashx", status: 200, text: skill},
    ], "download_file_as_text", {fileId: 5})

    assert.ok(!v.isError, text(v))
    assert.equal(text(v), skill)
  })

  void test("does not take a json file for an error response", async(t) => {
    const c = "{\"error\": \"not an error\", \"success\": false, \"message\": \"just data\"}"

    const [v] = await callMockedTool(t, () => [
      fileInfo(".json"),
      {method: "GET", path: "/filehandler.ashx", status: 200, text: c},
    ], "download_file_as_text", {fileId: 5})

    assert.ok(!v.isError, text(v))
    assert.equal(text(v), c)
  })

  void test("truncates a plain text file", async(t) => {
    const [v] = await callMockedTool(t, () => [
      fileInfo(".txt"),
      {method: "GET", path: "/filehandler.ashx", status: 200, text: "abcdefghij"},
    ], "download_file_as_text", {fileId: 5, offset: 2, limit: 3})

    assert.ok(!v.isError, text(v))
    assert.ok(text(v).startsWith("cde\n\n[Truncated:"), text(v))
    assert.ok(text(v).includes("offset=5"), text(v))
  })

  void test("reports the message of the file handler", async(t) => {
    const [v] = await callMockedTool(t, () => [
      fileInfo(".md"),
      {method: "GET", path: "/filehandler.ashx", status: 403, text: "You don't have enough permission to perform the operation"},
    ], "download_file_as_text", {fileId: 5})

    assert.ok(v.isError)
    assert.ok(text(v).includes("403 You don't have enough permission to perform the operation"), text(v))
  })

  void test("converts a document to text", async(t) => {
    const [v, s] = await callMockedTool(t, (base) => [
      fileInfo(".docx"),
      {method: "GET", path: "/api/2.0/files/settings", status: 200, json: envelope({extsConvertible: {".docx": [".pdf", ".txt"]}})},
      {method: "PUT", path: "/api/2.0/files/fileops/bulkdownload", status: 200, json: envelope([{id: "op", progress: 0, finished: false}])},
      {method: "GET", path: "/api/2.0/files/fileops", status: 200, json: envelope([{id: "op", progress: 100, finished: true, processed: "1", url: `${base}converted`}])},
      {method: "GET", path: "/converted", status: 200, text: "Converted text"},
    ], "download_file_as_text", {fileId: 5})

    assert.ok(!v.isError, text(v))
    assert.equal(text(v), "Converted text")
    assert.ok(!s.some((x) => x.url.pathname === "/filehandler.ashx"))
  })
})
