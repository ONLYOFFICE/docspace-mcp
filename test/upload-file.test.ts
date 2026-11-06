/**
 * @module
 */

import assert from "node:assert/strict"
import test from "node:test"
import type * as types from "@modelcontextprotocol/sdk/types.js"
import type {MockRoute, MockServed} from "./util.ts"
import {callMockedTool} from "./util.ts"

function envelope(response: unknown): unknown {
  return {response, count: 1, links: [], status: 0, statusCode: 200}
}

function texts(v: types.CallToolResult): string[] {
  return v.content.map((c) => {
    assert.ok(c.type === "text")
    return c.text
  })
}

function routes(title: string): MockRoute[] {
  return [
    {method: "POST", path: "/api/2.0/files/7/upload/create_session", status: 200, json: envelope({success: true, data: {id: "session"}})},
    {method: "POST", path: "/ChunkedUploader.ashx", status: 201, json: {success: true, data: {id: 5, title, version: 2}, message: ""}},
  ]
}

function session(s: MockServed[]): Record<string, unknown> {
  const c = s.find((x) => x.url.pathname.endsWith("/create_session"))
  assert.ok(c)
  return JSON.parse(c.body) as Record<string, unknown>
}

const skill = "---\nname: brand-voice\ndescription: Writes in the brand voice.\n---\n"

void test.suite("upload_file", () => {
  void test("uploads a new file by default", async(t) => {
    const [v, s] = await callMockedTool(t, () => routes("skill (1).md"), "upload_file", {parentId: 7, filename: "skill.md", content: skill})

    assert.ok(!v.isError, texts(v).join("\n"))
    assert.equal(session(s).createNewIfExist, true)
    assert.equal(texts(v).length, 1)
  })

  void test("overwrites the file with the same name", async(t) => {
    const [v, s] = await callMockedTool(t, () => routes("skill.md"), "upload_file", {parentId: 7, filename: "skill.md", content: skill, overwrite: true})

    assert.ok(!v.isError, texts(v).join("\n"))
    assert.equal(session(s).createNewIfExist, false)
    assert.equal(texts(v).length, 1)
  })

  void test("warns when the portal uploads a new file instead of overwriting", async(t) => {
    const [v] = await callMockedTool(t, () => routes("skill (1).md"), "upload_file", {parentId: 7, filename: "skill.md", content: skill, overwrite: true})

    assert.ok(!v.isError, texts(v).join("\n"))
    const [, w] = texts(v)
    assert.ok(w, "expected a warning")
    assert.ok(w.includes("did not overwrite skill.md"), w)
    assert.ok(w.includes("skill (1).md"), w)
  })
})
