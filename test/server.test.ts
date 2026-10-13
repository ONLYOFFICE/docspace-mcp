/**
 * @module test
 */

import assert from "node:assert/strict"
import test from "node:test"
import * as types from "@modelcontextprotocol/sdk/types.js"
import * as r from "../lib/util/result.ts"
import type {AsyncRequestListener, SetupMcpOptions} from "./util.ts"
import {onRequest, sendJson, setupHttp, setupMcp} from "./util.ts"

const body = {
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

    const s = await sendJson(res, 200, body)
    assert.ok(s.err === undefined)
  }
}

void test.suite("structured content", () => {
  void test("returns response data that conforms to output schema", async(t) => {
    const [hs, ha] = await setupHttp(t)

    const hl = test.mock.fn(listener())

    const hp = onRequest(t, hs, hl)

    const tf = async(): Promise<void> => {
      const so: SetupMcpOptions = {
        transport: "stdio",
        host: "",
        port: 0,
        env: {
          DOCSPACE_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
          DOCSPACE_API_KEY: "xxx",
        },
      }

      const cl = await setupMcp(t, so)

      // The client caches output schemas on listing tools and then validates
      // structured content against them on calling tools.
      const lr = await r.safeAsync(cl.listTools.bind(cl))
      assert.ok(lr.err === undefined)

      const cp: types.CallToolRequest["params"] = {
        name: "get_my_folder",
        arguments: {
          filters: {
            fields: [],
          },
        },
      }

      const cr = await r.safeAsync(cl.callTool.bind(cl), cp)
      assert.ok(cr.err === undefined)

      assert.ok(!cr.v.isError)
      assert.deepEqual(cr.v.structuredContent, body)
    }

    await Promise.race([hp, tf()])

    assert.ok(hl.mock.callCount() === 1)
  })

  void test("returns response data through call_tool meta tool", async(t) => {
    const [hs, ha] = await setupHttp(t)

    const hl = test.mock.fn(listener())

    const hp = onRequest(t, hs, hl)

    const tf = async(): Promise<void> => {
      const so: SetupMcpOptions = {
        transport: "stdio",
        host: "",
        port: 0,
        env: {
          DOCSPACE_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
          DOCSPACE_API_KEY: "xxx",
          DOCSPACE_DYNAMIC: "true",
        },
      }

      const cl = await setupMcp(t, so)

      const req: types.CallToolRequest = {
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

      const cr = await r.safeAsync(cl.request.bind(cl), req, types.CallToolResultSchema)
      assert.ok(cr.err === undefined)

      assert.ok(!cr.v.isError)
      assert.deepEqual(cr.v.structuredContent, body)
    }

    await Promise.race([hp, tf()])

    assert.ok(hl.mock.callCount() === 1)
  })

  void test("omits structured content for tool without output schema", async(t) => {
    const so: SetupMcpOptions = {
      transport: "stdio",
      host: "",
      port: 0,
      env: {
        DOCSPACE_BASE_URL: "http://localhost/",
        DOCSPACE_API_KEY: "xxx",
      },
    }

    const cl = await setupMcp(t, so)

    const req: types.CallToolRequest = {
      method: "tools/call",
      params: {
        name: "get_room_types",
      },
    }

    const cr = await r.safeAsync(cl.request.bind(cl), req, types.CallToolResultSchema)
    assert.ok(cr.err === undefined)

    assert.ok(!cr.v.isError)
    assert.ok(cr.v.structuredContent === undefined)
  })
})

void test.suite("input schema", () => {
  for (const dynamic of ["false", "true"]) {
    void test(`does not require properties with defaults when dynamic is ${dynamic}`, async(t) => {
      const so: SetupMcpOptions = {
        transport: "stdio",
        host: "",
        port: 0,
        env: {
          DOCSPACE_BASE_URL: "http://localhost/",
          DOCSPACE_API_KEY: "xxx",
          DOCSPACE_DYNAMIC: dynamic,
        },
      }

      const cl = await setupMcp(t, so)

      const lr = await r.safeAsync(cl.listTools.bind(cl))
      assert.ok(lr.err === undefined)
      assert.ok(lr.v.tools.length !== 0)

      const a: string[] = []

      for (const t of lr.v.tools) {
        collectRequiredDefaults(a, t.name, t.inputSchema)
      }

      assert.deepEqual(a, [])
    })
  }
})

function collectRequiredDefaults(a: string[], p: string, s: unknown): void {
  if (typeof s !== "object" || s === null) {
    return
  }

  const o = s as {
    properties?: Record<string, unknown>
    required?: string[]
    items?: unknown
    anyOf?: unknown[]
    oneOf?: unknown[]
    allOf?: unknown[]
  }

  if (o.properties) {
    for (const k of o.required ?? []) {
      const v = o.properties[k]
      if (typeof v === "object" && v !== null && "default" in v) {
        a.push(`${p}.${k}`)
      }
    }

    for (const [k, v] of Object.entries(o.properties)) {
      collectRequiredDefaults(a, `${p}.${k}`, v)
    }
  }

  if (o.items) {
    collectRequiredDefaults(a, `${p}[]`, o.items)
  }

  for (const [k, l] of [["anyOf", o.anyOf], ["oneOf", o.oneOf], ["allOf", o.allOf]] as const) {
    for (const [i, v] of (l ?? []).entries()) {
      collectRequiredDefaults(a, `${p}|${k}[${i}]`, v)
    }
  }
}
