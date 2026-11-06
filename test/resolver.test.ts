/**
 * @module
 */

import assert from "node:assert/strict"
import test from "node:test"
import type * as types from "@modelcontextprotocol/sdk/types.js"
import type * as core from "../lib/api/core.ts"
import * as apiExtra from "../lib/api/extra.ts"
import * as errors from "../lib/util/errors.ts"
import * as r from "../lib/util/result.ts"
import {callMockedTool} from "./util.ts"

function setupResolver(...statuses: apiExtra.Operation[][]): apiExtra.Resolver {
  let i = 0

  const c: apiExtra.ResolverClient = {
    files: {
      getOperationStatuses() {
        const s = statuses[Math.min(i, statuses.length - 1)]
        i += 1
        return Promise.resolve(r.ok([s, {} as core.Response]))
      },
    },
  }

  const v = new apiExtra.Resolver(c)
  v.limit = 3
  v.delay = 0

  return v
}

async function resolveError(v: apiExtra.Resolver, ...ops: apiExtra.Operation[]): Promise<[apiExtra.ResolverResponseError, string]> {
  const rr = await v.resolve(...ops)
  assert.ok(rr.err)
  assert.ok(rr.err instanceof apiExtra.ResolverResponseError)
  return [rr.err, errors.format(rr.err)]
}

void test.suite("resolver", () => {
  void test("resolves finished operations", async() => {
    const v = setupResolver([{id: "a", progress: 100, finished: true}])

    const rr = await v.resolve({id: "a", progress: 0, finished: false})
    assert.ok(!rr.err, rr.err && errors.format(rr.err))
  })

  void test("reports the error that the portal sets on an operation", async() => {
    const v = setupResolver([{id: "a", progress: 100, finished: true, error: "Only Markdown files (.md) can be added to an instructions room"}])

    const [e, m] = await resolveError(v, {id: "a", progress: 0, finished: false})

    assert.deepEqual(e.unresolved, ["a"])
    assert.equal(m, [
      "1 out of 1 operations are unresolved.",
      "\tOperation a: Only Markdown files (.md) can be added to an instructions room",
    ].join("\n"))
  })

  void test("reports an operation that does not finish", async() => {
    const v = setupResolver([{id: "a", progress: 50, finished: false}])

    const [e, m] = await resolveError(v, {id: "a", progress: 0, finished: false})

    assert.deepEqual(e.unresolved, ["a"])
    assert.ok(m.includes("Operation a did not finish after 3 status checks. It may still be running on the portal."), m)
  })

  void test("reports only the operations that are unresolved", async() => {
    const v = setupResolver([
      {id: "a", progress: 100, finished: true},
      {id: "b", progress: 100, finished: true, error: "The file is locked"},
      {id: "c", progress: 10, finished: false},
    ])

    const [e, m] = await resolveError(v,
      {id: "a", progress: 0, finished: false},
      {id: "b", progress: 0, finished: false},
      {id: "c", progress: 0, finished: false},
    )

    assert.deepEqual(e.unresolved, ["b", "c"])
    assert.ok(m.startsWith("2 out of 3 operations are unresolved."), m)
    assert.ok(!m.includes("Operation a"), m)
    assert.ok(m.includes("Operation b: The file is locked"), m)
    assert.ok(m.includes("Operation c did not finish"), m)
  })
})

void test.suite("resolver errors in tools", () => {
  void test("copy_batch_items reports the error of the portal", async(t) => {
    const [v] = await callMockedTool(t, () => [
      {method: "PUT", path: "/api/2.0/files/fileops/copy", status: 200, json: {response: [{id: "op", progress: 0, finished: false}], count: 1, links: [], status: 0, statusCode: 200}},
      {method: "GET", path: "/api/2.0/files/fileops", status: 200, json: {response: [{id: "op", progress: 100, finished: true, error: "Only Markdown files (.md) can be added to an instructions room"}], count: 1, links: [], status: 0, statusCode: 200}},
    ], "copy_batch_items", {fileIds: [5], destFolderId: 7})

    assert.ok(v.isError)
    const c = (v.content as types.TextContent[])[0]
    assert.ok(c.text.includes("Operation op: Only Markdown files (.md) can be added to an instructions room"), c.text)
  })
})
