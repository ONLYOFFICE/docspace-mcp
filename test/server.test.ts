/**
 * @module test
 */

import assert from "node:assert/strict"
import test from "node:test"
import * as types from "@modelcontextprotocol/sdk/types.js"
import * as r from "../lib/util/result.ts"
import type {AsyncRequestListener, SetupMcpOptions} from "./util.ts"
import {onRequest, sendJson, setupHttp, setupMcp} from "./util.ts"

let body = {
  response: {
    files: [],
    folders: [],
    current: {
      id: 1,
      title: "Documents",
    },
    total: 0,
  },
  count: 1,
  links: [
    {
      href: "http://localhost/api/2.0/files/@my",
      action: "GET",
    },
  ],
  status: 0,
  statusCode: 200,
}

function listener(): AsyncRequestListener {
  return async(req, res) => {
    assert.ok(req.method === "GET")
    assert.ok(req.url && req.url.startsWith("/api/2.0/files/@my"))

    let s = await sendJson(res, 200, body)
    assert.ok(s.err === undefined)
  }
}

void test.suite("structured content", () => {
  void test("returns response data that conforms to output schema", async(t) => {
    let [hs, ha] = await setupHttp(t)

    let hl = test.mock.fn(listener())

    let hp = onRequest(t, hs, hl)

    let tf = async(): Promise<void> => {
      let so: SetupMcpOptions = {
        transport: "stdio",
        host: "",
        port: 0,
        env: {
          DOCSPACE_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
          DOCSPACE_API_KEY: "xxx",
        },
      }

      let cl = await setupMcp(t, so)

      // The client caches output schemas on listing tools and then validates
      // structured content against them on calling tools.
      let lr = await r.safeAsync(cl.listTools.bind(cl))
      assert.ok(lr.err === undefined)

      let cp: types.CallToolRequest["params"] = {
        name: "get_my_folder",
        arguments: {
          filters: {
            fields: [],
          },
        },
      }

      let cr = await r.safeAsync(cl.callTool.bind(cl), cp)
      assert.ok(cr.err === undefined)

      assert.ok(!cr.v.isError)
      assert.deepEqual(cr.v.structuredContent, body)
    }

    await Promise.race([hp, tf()])

    assert.ok(hl.mock.callCount() === 1)
  })

  void test("returns response data through call_tool meta tool", async(t) => {
    let [hs, ha] = await setupHttp(t)

    let hl = test.mock.fn(listener())

    let hp = onRequest(t, hs, hl)

    let tf = async(): Promise<void> => {
      let so: SetupMcpOptions = {
        transport: "stdio",
        host: "",
        port: 0,
        env: {
          DOCSPACE_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
          DOCSPACE_API_KEY: "xxx",
          DOCSPACE_DYNAMIC: "true",
        },
      }

      let cl = await setupMcp(t, so)

      let req: types.CallToolRequest = {
        method: "tools/call",
        params: {
          name: "call_tool",
          arguments: {
            tool: "get_my_folder",
            input: {
              filters: {
                fields: [],
              },
            },
          },
        },
      }

      let cr = await r.safeAsync(cl.request.bind(cl), req, types.CallToolResultSchema)
      assert.ok(cr.err === undefined)

      assert.ok(!cr.v.isError)
      assert.deepEqual(cr.v.structuredContent, body)
    }

    await Promise.race([hp, tf()])

    assert.ok(hl.mock.callCount() === 1)
  })

  void test("applies default filters when filters are omitted", async(t) => {
    let [hs, ha] = await setupHttp(t)

    let hl = test.mock.fn<AsyncRequestListener>(async(req, res) => {
      assert.ok(req.method === "GET")
      assert.ok(req.url)

      let u = new URL(req.url, "http://localhost/")
      assert.ok(u.pathname === "/api/2.0/files/@my")
      assert.ok(u.searchParams.get("count") === "30")
      let f = u.searchParams.getAll("fields")
      assert.ok(f.includes("files.title"))
      assert.ok(f.includes("current.security"))
      assert.ok(!f.includes("files.security"))
      assert.ok(!f.includes("folders.security"))

      let s = await sendJson(res, 200, body)
      assert.ok(s.err === undefined)
    })

    let hp = onRequest(t, hs, hl)

    let tf = async(): Promise<void> => {
      let so: SetupMcpOptions = {
        transport: "stdio",
        host: "",
        port: 0,
        env: {
          DOCSPACE_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
          DOCSPACE_API_KEY: "xxx",
        },
      }

      let cl = await setupMcp(t, so)

      let lr = await r.safeAsync(cl.listTools.bind(cl))
      assert.ok(lr.err === undefined)

      let lt = lr.v.tools.find((t) => t.name === "get_my_folder")
      assert.ok(lt)
      assert.ok(!lt.inputSchema.required?.includes("filters"))

      let cp: types.CallToolRequest["params"] = {
        name: "get_my_folder",
        arguments: {},
      }

      let cr = await r.safeAsync(cl.callTool.bind(cl), cp)
      assert.ok(cr.err === undefined)

      assert.ok(!cr.v.isError)
      assert.deepEqual(cr.v.structuredContent, body)
    }

    await Promise.race([hp, tf()])

    assert.ok(hl.mock.callCount() === 1)
  })

  void test("omits structured content for tool without output schema", async(t) => {
    let so: SetupMcpOptions = {
      transport: "stdio",
      host: "",
      port: 0,
      env: {
        DOCSPACE_BASE_URL: "http://localhost/",
        DOCSPACE_API_KEY: "xxx",
      },
    }

    let cl = await setupMcp(t, so)

    let req: types.CallToolRequest = {
      method: "tools/call",
      params: {
        name: "get_room_types",
      },
    }

    let cr = await r.safeAsync(cl.request.bind(cl), req, types.CallToolResultSchema)
    assert.ok(cr.err === undefined)

    assert.ok(!cr.v.isError)
    assert.ok(cr.v.structuredContent === undefined)
  })
})
