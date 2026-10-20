/**
 * @module test
 */

import assert from "node:assert/strict"
import test from "node:test"
import type * as client from "@modelcontextprotocol/sdk/client/index.js"
import type * as types from "@modelcontextprotocol/sdk/types.js"
import * as r from "../lib/util/result.ts"
import type {AsyncRequestListener, SetupMcpOptions} from "./util.ts"
import {onRequest, readHttpData, sendJson, setupHttp, setupMcp} from "./util.ts"

const file = {
  id: 10,
  title: "Report.docx",
  version: 1,
  webUrl: "http://localhost/doceditor?fileid=10",
  viewUrl: "http://localhost/filehandler.ashx?action=download&fileid=10",
  contentLength: "8.2 KB",
  folderId: 5,
  fileExst: ".docx",
  createdBy: {
    id: "00000000-0000-0000-0000-000000000001",
    displayName: "Test User",
  },
}

function wrap(response: unknown): unknown {
  return {
    response,
    count: 1,
    links: [],
    status: 0,
    statusCode: 200,
  }
}

// Answers the builder request with an operation and every status request with
// that operation finished with the given files and error, and keeps the bodies
// of the builder requests.
function listener(files: unknown[], bodies: unknown[], error: string): AsyncRequestListener {
  return async(req, res) => {
    if (req.method === "POST" && req.url && req.url.startsWith("/api/2.0/docs/builder")) {
      assert.ok(req.headers["content-type"]?.startsWith("application/json"))

      const d = await readHttpData(req)
      assert.ok(d.err === undefined)

      const b = r.safeSync(JSON.parse, Buffer.concat(d.v).toString("utf8"))
      assert.ok(b.err === undefined)

      bodies.push(b.v)

      const s = await sendJson(res, 200, wrap({id: "op", progress: 0, finished: false}))
      assert.ok(s.err === undefined)

      return
    }

    if (req.method === "GET" && req.url && req.url.startsWith("/api/2.0/files/fileops")) {
      const o = {
        id: "op",
        status: 2,
        processed: "0",
        progress: 100,
        finished: true,
        files,
        error,
      }

      const s = await sendJson(res, 200, wrap([o]))
      assert.ok(s.err === undefined)

      return
    }

    assert.fail(`Unexpected request: ${req.method} ${req.url}`)
  }
}

async function setup(t: test.TestContext, files: unknown[], bodies: unknown[], error = ""): Promise<[client.Client, Promise<void>]> {
  const [hs, ha] = await setupHttp(t)

  const hp = onRequest(t, hs, listener(files, bodies, error))

  const so: SetupMcpOptions = {
    transport: "stdio",
    host: "",
    port: 0,
    env: {
      DOCSPACE_BASE_URL: `http://[${ha.address}]:${ha.port}/`,
      DOCSPACE_API_KEY: "xxx",
      DOCSPACE_FILE_OPERATION_INTERVAL: "10",
    },
  }

  const cl = await setupMcp(t, so)

  // The client caches output schemas on listing tools and then validates
  // structured content against them on calling tools.
  const lr = await r.safeAsync(cl.listTools.bind(cl))
  assert.ok(lr.err === undefined)

  return [cl, hp]
}

void test.suite("run builder script", () => {
  void test("returns the default fields of the saved files", async(t) => {
    const bodies: unknown[] = []

    const [cl, hp] = await setup(t, [file], bodies)

    const tf = async(): Promise<void> => {
      const cp: types.CallToolRequest["params"] = {
        name: "run_builder_script",
        arguments: {
          script: "builder.CreateFile(\"docx\")\nbuilder.SaveFile(\"docx\", \"Report.docx\")\nbuilder.CloseFile()",
          folderId: 5,
        },
      }

      const cr = await r.safeAsync(cl.callTool.bind(cl), cp)
      assert.ok(cr.err === undefined)

      assert.ok(!cr.v.isError, JSON.stringify(cr.v.content))

      const x = {
        files: [
          {
            id: 10,
            title: "Report.docx",
            version: 1,
            webUrl: "http://localhost/doceditor?fileid=10",
            folderId: 5,
          },
        ],
      }

      assert.deepEqual(cr.v.structuredContent, x)
    }

    await Promise.race([hp, tf()])
  })

  void test("returns the fields of the saved files asked for in filters", async(t) => {
    const bodies: unknown[] = []

    const [cl, hp] = await setup(t, [file], bodies)

    const tf = async(): Promise<void> => {
      const cp: types.CallToolRequest["params"] = {
        name: "run_builder_script",
        arguments: {
          script: "builder.CreateFile(\"docx\")\nbuilder.SaveFile(\"docx\", \"Report.docx\")\nbuilder.CloseFile()",
          folderId: 5,
          filters: {
            fields: ["id", "createdBy.displayName", "contentLength", "shared"],
          },
        },
      }

      const cr = await r.safeAsync(cl.callTool.bind(cl), cp)
      assert.ok(cr.err === undefined)

      assert.ok(!cr.v.isError, JSON.stringify(cr.v.content))

      // The file has no shared field, so the response has none either.
      const x = {
        files: [
          {
            id: 10,
            createdBy: {
              displayName: "Test User",
            },
            contentLength: "8.2 KB",
          },
        ],
      }

      assert.deepEqual(cr.v.structuredContent, x)
    }

    await Promise.race([hp, tf()])
  })

  void test("omits a nested field whose leaf is missing", async(t) => {
    const bodies: unknown[] = []

    const f = {...file, createdBy: {id: "00000000-0000-0000-0000-000000000001"}}

    const [cl, hp] = await setup(t, [f], bodies)

    const tf = async(): Promise<void> => {
      const cp: types.CallToolRequest["params"] = {
        name: "run_builder_script",
        arguments: {
          script: "builder.CreateFile(\"docx\")\nbuilder.SaveFile(\"docx\", \"Report.docx\")\nbuilder.CloseFile()",
          folderId: 5,
          filters: {
            fields: ["id", "createdBy.displayName"],
          },
        },
      }

      const cr = await r.safeAsync(cl.callTool.bind(cl), cp)
      assert.ok(cr.err === undefined)

      assert.ok(!cr.v.isError, JSON.stringify(cr.v.content))

      // The creator has no displayName field, so the response has no empty
      // createdBy object either.
      const x = {
        files: [
          {
            id: 10,
          },
        ],
      }

      assert.deepEqual(cr.v.structuredContent, x)
    }

    await Promise.race([hp, tf()])
  })

  void test("sends the script without the filters", async(t) => {
    const bodies: unknown[] = []

    const [cl, hp] = await setup(t, [file], bodies)

    const tf = async(): Promise<void> => {
      const cp: types.CallToolRequest["params"] = {
        name: "run_builder_script",
        arguments: {
          script: "builder.OpenFile(\"10\")\nbuilder.SaveFile(\"docx\", \"Report.docx\")\nbuilder.CloseFile()",
          folderId: 5,
          outputs: {
            "Report.docx": {
              fileId: 10,
            },
          },
          argument: {
            title: "Report",
          },
          filters: {
            fields: ["id"],
          },
        },
      }

      const cr = await r.safeAsync(cl.callTool.bind(cl), cp)
      assert.ok(cr.err === undefined)

      assert.ok(!cr.v.isError, JSON.stringify(cr.v.content))

      const x = [
        {
          script: "builder.OpenFile(\"10\")\nbuilder.SaveFile(\"docx\", \"Report.docx\")\nbuilder.CloseFile()",
          folderId: 5,
          outputs: {
            "Report.docx": {
              fileId: 10,
            },
          },
          argument: {
            title: "Report",
          },
        },
      ]

      assert.deepEqual(bodies, x)
    }

    await Promise.race([hp, tf()])
  })

  void test("refuses outputs entries without exactly one of fileId and folderId", async(t) => {
    const cases = [
      [{fileId: 10, folderId: 5}, "Exactly one of fileId and folderId"],
      [{}, "Exactly one of fileId and folderId"],
      [{title: "Copy.docx"}, "Exactly one of fileId and folderId"],
      [{fileId: 10, title: "Copy.docx"}, "Title can only be provided with folderId"],
    ] as const

    const bodies: unknown[] = []

    const [cl, hp] = await setup(t, [file], bodies)

    const tf = async(): Promise<void> => {
      for (const [o, m] of cases) {
        const cp: types.CallToolRequest["params"] = {
          name: "run_builder_script",
          arguments: {
            script: "builder.OpenFile(\"10\")\nbuilder.SaveFile(\"docx\", \"Report.docx\")\nbuilder.CloseFile()",
            outputs: {
              "Report.docx": o,
            },
          },
        }

        const cr = await r.safeAsync(cl.callTool.bind(cl), cp)
        assert.ok(cr.err === undefined)

        assert.ok(cr.v.isError)

        const c = cr.v.content as types.TextContent[]
        assert.ok(c[0].text.includes(m), c[0].text)
      }

      assert.deepEqual(bodies, [])
    }

    await Promise.race([hp, tf()])
  })

  void test("returns error when the operation saves no files", async(t) => {
    const bodies: unknown[] = []

    const [cl, hp] = await setup(t, [], bodies)

    const tf = async(): Promise<void> => {
      const cp: types.CallToolRequest["params"] = {
        name: "run_builder_script",
        arguments: {
          script: "builder.CreateFile(\"docx\")\nbuilder.CloseFile()",
          folderId: 5,
        },
      }

      const cr = await r.safeAsync(cl.callTool.bind(cl), cp)
      assert.ok(cr.err === undefined)

      assert.ok(cr.v.isError)
      assert.ok(cr.v.structuredContent === undefined)

      const c = cr.v.content as types.TextContent[]
      assert.ok(c[0].text.includes("No items processed"), c[0].text)
    }

    await Promise.race([hp, tf()])
  })

  void test("explains the error code of a failed script", async(t) => {
    const bodies: unknown[] = []

    const [cl, hp] = await setup(t, [], bodies, "Error occurred in the Documents Service (convertation, error -3)")

    const tf = async(): Promise<void> => {
      const cp: types.CallToolRequest["params"] = {
        name: "run_builder_script",
        arguments: {
          script: "builder.CreateFile(\"docx\")\nthrow new Error(\"boom\")",
          folderId: 5,
        },
      }

      const cr = await r.safeAsync(cl.callTool.bind(cl), cp)
      assert.ok(cr.err === undefined)

      assert.ok(cr.v.isError)

      const c = cr.v.content as types.TextContent[]
      assert.ok(c[0].text.includes("error -3"), c[0].text)
      assert.ok(c[0].text.includes("Document Builder error -3 (document generation error)"), c[0].text)
      assert.ok(c[0].text.includes("get_office_api_reference"), c[0].text)
      assert.ok(!c[0].text.includes("No items processed"), c[0].text)
    }

    await Promise.race([hp, tf()])
  })

  void test("returns the error of a failed script without a code as is", async(t) => {
    const bodies: unknown[] = []

    const [cl, hp] = await setup(t, [], bodies, "Error occurred in the Documents Service (convertation)")

    const tf = async(): Promise<void> => {
      const cp: types.CallToolRequest["params"] = {
        name: "run_builder_script",
        arguments: {
          script: "builder.CreateFile(\"docx\")\nthrow new Error(\"boom\")",
          folderId: 5,
        },
      }

      const cr = await r.safeAsync(cl.callTool.bind(cl), cp)
      assert.ok(cr.err === undefined)

      assert.ok(cr.v.isError)

      const c = cr.v.content as types.TextContent[]
      assert.ok(c[0].text.includes("Error occurred in the Documents Service (convertation)"), c[0].text)
      assert.ok(!c[0].text.includes("Document Builder error"), c[0].text)
      assert.ok(!c[0].text.includes("No items processed"), c[0].text)
    }

    await Promise.race([hp, tf()])
  })
})
