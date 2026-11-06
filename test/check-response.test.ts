/**
 * @module
 */

import assert from "node:assert/strict"
import test from "node:test"
import * as core from "../lib/api/core.ts"

async function check(status: number, body: unknown): Promise<string> {
  const req = new Request("http://localhost/ChunkedUploader.ashx?uid=x", {method: "POST"})
  const res = Response.json(body, {status})

  const err = await core.checkSharedResponse(req, res)
  assert.ok(err instanceof core.ResponseError)

  return err.message
}

void test.suite("checkSharedResponse", () => {
  void test("says that the portal refused a request answered with 200 and an error", async() => {
    const m = await check(200, {success: false, message: "The skill file must start with a YAML frontmatter block"})

    assert.equal(m, "POST http://localhost/ChunkedUploader.ashx?uid=x: refused by the portal: The skill file must start with a YAML frontmatter block")
  })

  void test("takes the status from the envelope of a request answered with 200", async() => {
    const m = await check(200, {status: 1, statusCode: 403, error: {message: "Access denied", type: "x", stack: "", hresult: 0}})

    assert.equal(m, "POST http://localhost/ChunkedUploader.ashx?uid=x: 403 Access denied")
  })

  void test("does not take a status below 400 from the envelope", async() => {
    const m = await check(200, {status: 1, statusCode: 200, error: {message: "Something failed", type: "x", stack: "", hresult: 0}})

    assert.equal(m, "POST http://localhost/ChunkedUploader.ashx?uid=x: refused by the portal: Something failed")
  })

  void test("keeps the http status of an error response", async() => {
    const m = await check(403, {status: 1, statusCode: 403, error: {message: "Access denied", type: "x", stack: "", hresult: 0}})

    assert.equal(m, "POST http://localhost/ChunkedUploader.ashx?uid=x: 403 Access denied")
  })

  void test("keeps the http status of an error without a body", async() => {
    const req = new Request("http://localhost/api/2.0/files/file/5", {method: "GET"})
    const res = new Response(null, {status: 404, statusText: "Not Found"})

    const err = await core.checkSharedResponse(req, res)
    assert.ok(err instanceof core.ResponseError)
    assert.equal(err.message, "GET http://localhost/api/2.0/files/file/5: 404 Not Found")
  })

  void test("passes a successful response", async() => {
    const req = new Request("http://localhost/api/2.0/files/file/5", {method: "GET"})
    const res = Response.json({response: {id: 5}, count: 1, links: [], status: 0, statusCode: 200})

    const err = await core.checkSharedResponse(req, res)
    assert.equal(err, undefined)
  })
})
