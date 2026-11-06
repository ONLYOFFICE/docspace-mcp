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

type Uploaded = {
  id: number
  title: string
  version: number
}

// The routes of an upload to folder 7. The check answers with the titles that
// already belong to a file in the folder, when it is set.
function routes(uploaded: Uploaded, existing?: string[]): MockRoute[] {
  const r: MockRoute[] = [
    {method: "POST", path: "/api/2.0/files/7/upload/create_session", status: 200, json: envelope({success: true, data: {id: "session"}})},
    {method: "POST", path: "/ChunkedUploader.ashx", status: 201, json: {success: true, data: uploaded, message: ""}},
  ]
  if (existing) {
    r.push({method: "POST", path: "/api/2.0/files/7/upload/check", status: 200, json: envelope(existing)})
  }
  return r
}

function served(s: MockServed[], p: string): MockServed | undefined {
  return s.find((x) => x.url.pathname.endsWith(p))
}

function session(s: MockServed[]): Record<string, unknown> {
  const c = served(s, "/create_session")
  assert.ok(c)
  return JSON.parse(c.body) as Record<string, unknown>
}

function checked(s: MockServed[]): unknown {
  const c = served(s, "/upload/check")
  assert.ok(c, "expected an upload check")
  return JSON.parse(c.body)
}

const skill = "---\nname: brand-voice\ndescription: Writes in the brand voice.\n---\n"

void test.suite("upload_file", () => {
  void test("uploads a new file by default without checking the folder", async(t) => {
    const [v, s] = await callMockedTool(t, () => routes({id: 5, title: "skill (1).md", version: 1}), "upload_file", {parentId: 7, filename: "skill.md", content: skill})

    assert.ok(!v.isError, texts(v).join("\n"))
    assert.equal(session(s).createNewIfExist, true)
    assert.equal(served(s, "/upload/check"), undefined)
    assert.equal(texts(v).length, 1)
  })

  void test("overwrites the file with the same name", async(t) => {
    const [v, s] = await callMockedTool(t, () => routes({id: 5, title: "skill.md", version: 2}, ["skill.md"]), "upload_file", {parentId: 7, filename: "skill.md", content: skill, overwrite: true})

    assert.ok(!v.isError, texts(v).join("\n"))
    assert.equal(session(s).createNewIfExist, false)
    assert.deepEqual(checked(s), {filesTitle: ["skill.md"]})
    assert.equal(texts(v).length, 1)
  })

  void test("does not warn when the portal overwrites a file named in another case", async(t) => {
    const [v] = await callMockedTool(t, () => routes({id: 5, title: "summarize-report.md", version: 3}, ["Summarize-Report.md"]), "upload_file", {parentId: 7, filename: "Summarize-Report.md", content: skill, overwrite: true})

    assert.ok(!v.isError, texts(v).join("\n"))
    assert.equal(texts(v).length, 1)
  })

  void test("does not warn when no file had the name the portal stores", async(t) => {
    const [v, s] = await callMockedTool(t, () => routes({id: 5, title: "kb_notes.md", version: 1}, []), "upload_file", {parentId: 7, filename: " kb:notes.md", content: skill, overwrite: true})

    assert.ok(!v.isError, texts(v).join("\n"))
    assert.deepEqual(checked(s), {filesTitle: ["kb_notes.md"]})
    assert.equal(texts(v).length, 1)
  })

  for (const [name, title] of [
    [`${"a".repeat(200)}.md`, `${"a".repeat(167)}.md`],
    [`${"a".repeat(100)}.${"b".repeat(100)}`, `${"a".repeat(100)}.${"b".repeat(69)}`],
    ["notes 😀.md", "notes __.md"],
  ] as const) {
    void test(`checks the name ${name.slice(0, 16)}… as the portal stores it`, async(t) => {
      const [v, s] = await callMockedTool(t, () => routes({id: 5, title, version: 1}, []), "upload_file", {parentId: 7, filename: name, content: skill, overwrite: true})

      assert.ok(!v.isError, texts(v).join("\n"))
      assert.deepEqual(checked(s), {filesTitle: [title]})
    })
  }

  void test("warns when the portal adds a second file instead of overwriting", async(t) => {
    const [v] = await callMockedTool(t, () => routes({id: 6, title: "kb_notes.md", version: 1}, ["kb_notes.md"]), "upload_file", {parentId: 7, filename: "kb_notes.md", content: skill, overwrite: true})

    assert.ok(!v.isError, texts(v).join("\n"))
    const [, w] = texts(v)
    assert.ok(w, "expected a warning")
    assert.ok(w.includes("did not overwrite kb_notes.md and added a new file (file 6) with the same name"), w)
    assert.ok(w.includes("delete_file"), w)
  })

  void test("reports a refused upload check", async(t) => {
    const [v, s] = await callMockedTool(t, () => [
      {method: "POST", path: "/api/2.0/files/7/upload/check", status: 403, json: {status: 1, statusCode: 403, error: {message: "You don't have enough permission to create", type: "x", stack: "", hresult: 0}}},
    ], "upload_file", {parentId: 7, filename: "skill.md", content: skill, overwrite: true})

    assert.ok(v.isError)
    assert.ok(texts(v)[0].startsWith("Checking upload conflicts."), texts(v)[0])
    assert.equal(served(s, "/create_session"), undefined)
  })

  void test("reports a file that the portal refuses without the http status", async(t) => {
    const [v] = await callMockedTool(t, () => [
      routes({id: 5, title: "skill.md", version: 1})[0],
      {method: "POST", path: "/ChunkedUploader.ashx", status: 200, json: {success: false, message: "The skill file must start with a YAML frontmatter block"}},
    ], "upload_file", {parentId: 7, filename: "skill.md", content: "# No frontmatter\n"})

    assert.ok(v.isError)
    const [m] = texts(v)
    assert.ok(m.includes(": refused by the portal: The skill file must start with a YAML frontmatter block"), m)
    assert.ok(!m.includes(": 200 "), m)
  })
})
