/**
 * @module test
 */

import assert from "node:assert/strict"
import test from "node:test"
import * as types from "@modelcontextprotocol/sdk/types.js"
import * as core from "../lib/api/core.ts"
import * as r from "../lib/util/result.ts"
import type {AsyncRequestListener, SetupMcpOptions} from "./util.ts"
import {onRequest, readHttpData, sendJson, setupHttp, setupMcp} from "./util.ts"

type Case = {
  name: string
  tool: string
  arguments: Record<string, unknown>
  path: string
  response: Record<string, unknown>
}

const cases: Case[] = [
  {
    name: "instructions room",
    tool: "get_room_info",
    arguments: {roomId: 10},
    path: "/api/2.0/files/rooms/10",
    response: {
      id: 10,
      title: "Instructions",
      parentId: 1,
      roomType: 10,
      type: 38,
    },
  },
  {
    name: "knowledge room",
    tool: "get_room_info",
    arguments: {roomId: 11},
    path: "/api/2.0/files/rooms/11",
    response: {
      id: 11,
      title: "Knowledge",
      parentId: 1,
      roomType: 11,
      type: 39,
    },
  },
  {
    name: "ai project",
    tool: "get_room_info",
    arguments: {roomId: 12},
    path: "/api/2.0/files/rooms/12",
    response: {
      id: 12,
      title: "Project",
      parentId: 1,
      roomType: 12,
      type: 40,
    },
  },
  {
    name: "legacy ai agent",
    tool: "get_room_info",
    arguments: {roomId: 9},
    path: "/api/2.0/files/rooms/9",
    response: {
      id: 9,
      title: "Agent",
      parentId: 1,
      roomType: 9,
      type: 31,
    },
  },
  {
    name: "ai rooms root",
    tool: "get_folder_info",
    arguments: {folderId: 1},
    path: "/api/2.0/files/folder/1",
    response: {
      id: 1,
      title: "AI rooms",
      parentId: 0,
      type: 41,
    },
  },
]

function listener(c: Case, body: unknown): AsyncRequestListener {
  return async(req, res) => {
    assert.ok(req.method === "GET")
    assert.ok(req.url && req.url.startsWith(c.path))

    const s = await sendJson(res, 200, body)
    assert.ok(s.err === undefined)
  }
}

void test.suite("ai rooms in existing tools", () => {
  for (const c of cases) {
    void test(`returns ${c.name} through ${c.tool}`, async(t) => {
      const body = {
        response: c.response,
        count: 1,
        links: [
          {
            href: `http://localhost${c.path}`,
            action: "GET",
          },
        ],
        status: 0,
        statusCode: 200,
      }

      const [hs, ha] = await setupHttp(t)

      const hl = test.mock.fn(listener(c, body))

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
          name: c.tool,
          arguments: {
            ...c.arguments,
            filters: {
              fields: [],
            },
          },
        }

        const cr = await r.safeAsync(cl.callTool.bind(cl), cp)
        assert.ok(cr.err === undefined)

        assert.ok(!cr.v.isError, JSON.stringify(cr.v.content))
        assert.deepEqual(cr.v.structuredContent, body)
      }

      await Promise.race([hp, tf()])

      assert.ok(hl.mock.callCount() === 1)
    })
  }
})

// The payloads below follow the responses of a portal on version 4.1.0.

const logo = {
  original: "",
  large: "",
  medium: "",
  small: "",
  color: "7757D9",
}

void test.suite("ai room schemas", () => {
  void test("parses ai project sources", () => {
    const v = {
      instructionsRooms: [{id: 10, title: "Instructions", logo}],
      knowledgeRooms: [{id: 11, title: "Knowledge", logo}],
    }
    const p = core.AiProjectSourcesDtoSchema.safeParse(v)
    assert.ok(p.success)
    assert.deepEqual(p.data, v)
  })

  void test("parses ai skills", () => {
    const v = {
      rooms: [
        {
          id: 10,
          title: "Instructions",
          logo,
          skills: [{id: "100", name: "brand-voice", description: "Writes in the brand voice."}],
        },
      ],
    }
    const p = core.AiSkillsDtoSchema.safeParse(v)
    assert.ok(p.success)
    assert.deepEqual(p.data, v)
  })

  for (const v of [{}, {profileId: null}, {profileId: "019ed117-6bd3-7861-ab75-44f72d17d724"}]) {
    void test(`parses ai project model ${JSON.stringify(v)}`, () => {
      const p = core.AiProjectModelDtoSchema.safeParse(v)
      assert.ok(p.success)
      assert.deepEqual(p.data, v)
    })
  }

  void test("parses ai profiles", () => {
    const v = [
      {
        id: "019ed117-6bd3-7861-ab75-44f72d17d724",
        name: "Chat model",
        providerType: "onlyoffice",
        baseUrl: "http://localhost/",
        modelId: "chat-model",
        createdAt: -62135596800000,
        reasoning: true,
        reasoningSupport: {thinks: true, canDisable: false, depths: ["low"], defaultDepth: "low"},
        capabilities: 385,
        canUseTool: true,
        useResponsesApi: false,
      },
      {
        id: "019f60b7-9118-76da-b4e2-6e9a7374b814",
        name: "Image model",
        providerType: "onlyoffice",
        baseUrl: "http://localhost/",
        modelId: "image-model",
        capabilities: 2,
        canUseTool: false,
      },
    ]
    const p = core.AiProfileSchema.array().safeParse(v)
    assert.ok(p.success)
    assert.deepEqual(p.data, v)
  })

  void test("parses ai settings", () => {
    const v = {
      vectorizationEnabled: true,
      vectorizationNeedReset: false,
      aiReady: true,
      embeddingModel: "text-embedding-3-small",
      systemAiEnabled: true,
      recommendedModelForForms: "forms-model",
      toolPermissionMode: 1,
    }
    const p = core.AiSettingsDtoSchema.safeParse(v)
    assert.ok(p.success)
    assert.deepEqual(p.data, v)
  })

  for (const vectorizationStatus of [0, 1, 2, null]) {
    void test(`parses file with vectorization status ${vectorizationStatus}`, () => {
      const v = {id: 1, title: "notes.txt", vectorizationStatus}
      const p = core.FileDtoSchema.safeParse(v)
      assert.ok(p.success)
      assert.deepEqual(p.data, v)
    })
  }

  void test("rejects unknown vectorization status", () => {
    const p = core.FileDtoSchema.safeParse({id: 1, vectorizationStatus: 3})
    assert.ok(!p.success)
  })

  void test("accepts only ai room types in ai rooms folder filters", () => {
    const a = core.GetAiRoomsFolderFiltersSchema.safeParse({type: [10, 11, 12], fields: []})
    assert.ok(a.success)
    assert.ok(!("searchArea" in a.data))

    const b = core.GetAiRoomsFolderFiltersSchema.safeParse({type: [1], fields: []})
    assert.ok(!b.success)
  })

  void test("keeps ai room types out of create room requests", () => {
    const a = core.CreateRoomRequestDtoSchema.safeParse({title: "x", roomType: 10})
    assert.ok(!a.success)

    const b = core.CreateAiRoomRequestDtoSchema.safeParse({title: "x", roomType: 11})
    assert.ok(b.success)

    const c = core.CreateAiRoomRequestDtoSchema.safeParse({title: "x", roomType: 6})
    assert.ok(!c.success)
  })
})

type Exchange = {
  method: string
  url: URL
  body: unknown
}

function setupClient(status: number, body?: unknown): [core.Client, Exchange[]] {
  const a: Exchange[] = []

  const fetch: typeof globalThis.fetch = async(input) => {
    assert.ok(input instanceof Request)

    const t = await input.text()

    a.push({
      method: input.method,
      url: new URL(input.url),
      body: t === "" ? undefined : JSON.parse(t),
    })

    if (body === undefined) {
      return new Response(null, {status})
    }

    return new Response(JSON.stringify(body), {
      status,
      headers: {"Content-Type": "application/json"},
    })
  }

  const c = new core.Client({userAgent: "", baseUrl: "http://localhost/", fetch})

  return [c, a]
}

function envelope(response: unknown): unknown {
  return {response, count: 1, links: [], status: 0, statusCode: 200}
}

function messages(err: unknown): string {
  const a: string[] = []
  while (err instanceof Error) {
    a.push(err.message)
    err = err.cause
  }
  return a.join("\n")
}

void test.suite("ai rooms client", () => {
  void test("gets the ai rooms section", async() => {
    const [c, a] = setupClient(200, envelope({files: [], folders: [], current: {id: 1}, total: 0}))

    const r = await c.files.getAiRoomsFolder({type: [10, 12], fields: []})
    assert.ok(r.err === undefined)

    assert.ok(a.length === 1)
    assert.ok(a[0].method === "GET")
    assert.ok(a[0].url.pathname === "/api/2.0/files/rooms")
    assert.ok(a[0].url.searchParams.get("searchArea") === "AiHub")
    assert.deepEqual(a[0].url.searchParams.getAll("type"), ["10", "12"])
  })

  void test("creates an ai room", async() => {
    const [c, a] = setupClient(200, envelope({id: 1, title: "Project", roomType: 12}))

    const r = await c.files.createAiRoom({title: "Project", roomType: 12, tags: ["a"], color: "7757D9"})
    assert.ok(r.err === undefined)
    assert.ok(r.v[0].roomType === 12)

    assert.ok(a[0].method === "POST")
    assert.ok(a[0].url.pathname === "/api/2.0/files/rooms")
    assert.deepEqual(a[0].body, {title: "Project", roomType: 12, tags: ["a"], color: "7757D9"})
  })

  void test("deletes a room", async() => {
    const [c, a] = setupClient(200, envelope({id: "op", progress: 0, finished: false}))

    const r = await c.files.deleteRoom(1, {deleteAfter: false})
    assert.ok(r.err === undefined)
    assert.ok(r.v[0].id === "op")

    assert.ok(a[0].method === "DELETE")
    assert.ok(a[0].url.pathname === "/api/2.0/files/rooms/1")
    assert.deepEqual(a[0].body, {deleteAfter: false})
  })

  void test("gets ai project sources", async() => {
    const [c, a] = setupClient(200, envelope({instructionsRooms: [{id: 10}], knowledgeRooms: []}))

    const r = await c.files.getAiProjectSources(12)
    assert.ok(r.err === undefined)
    assert.deepEqual(r.v[0], {instructionsRooms: [{id: 10}], knowledgeRooms: []})

    assert.ok(a[0].method === "GET")
    assert.ok(a[0].url.pathname === "/api/2.0/files/rooms/12/sources")
  })

  for (const [name, method] of [["links", "POST"], ["unlinks", "DELETE"]] as const) {
    void test(`${name} ai project sources answered with no content`, async() => {
      const [c, a] = setupClient(204)

      const r = method === "POST" ?
        await c.files.linkAiProjectSources(12, {roomIds: [10, 11]}) :
        await c.files.unlinkAiProjectSources(12, {roomIds: [10, 11]})
      assert.ok(r.err === undefined, messages(r.err))
      assert.ok(r.v.response.status === 204)

      assert.ok(a[0].method === method)
      assert.ok(a[0].url.pathname === "/api/2.0/files/rooms/12/sources")
      assert.deepEqual(a[0].body, {roomIds: [10, 11]})
    })
  }

  void test("gets ai room skills", async() => {
    const [c, a] = setupClient(200, envelope({rooms: [{id: 10, skills: [{id: "1", name: "a", description: "b"}]}]}))

    const r = await c.files.getAiRoomSkills(12)
    assert.ok(r.err === undefined)
    assert.ok(r.v[0].rooms?.[0].skills?.[0].name === "a")

    assert.ok(a[0].url.pathname === "/api/2.0/files/rooms/12/skills")
  })

  void test("gets an ai project model that is not set", async() => {
    const [c, a] = setupClient(200, envelope({}))

    const r = await c.files.getAiProjectModel(12)
    assert.ok(r.err === undefined)
    assert.deepEqual(r.v[0], {})

    assert.ok(a[0].url.pathname === "/api/2.0/files/rooms/12/model")
  })

  void test("updates an ai project model", async() => {
    const id = "019ed117-6bd3-7861-ab75-44f72d17d724"
    const [c, a] = setupClient(200, envelope({profileId: id}))

    const r = await c.files.updateAiProjectModel(12, {profileId: id})
    assert.ok(r.err === undefined)
    assert.ok(r.v[0].profileId === id)

    assert.ok(a[0].method === "PUT")
    assert.deepEqual(a[0].body, {profileId: id})
  })

  void test("gets the ai config inside the response envelope", async() => {
    const [c, a] = setupClient(200, envelope({aiReady: true, vectorizationEnabled: false}))

    const r = await c.ai.getConfig()
    assert.ok(r.err === undefined)
    assert.ok(r.v[0].aiReady === true)
    assert.ok(r.v[0].vectorizationEnabled === false)

    assert.ok(a[0].url.pathname === "/api/2.0/ai/config")
  })

  void test("gets ai profiles without the response envelope", async() => {
    const [c, a] = setupClient(200, [
      {id: "1", name: "Chat", providerType: "onlyoffice", baseUrl: "http://localhost/", modelId: "chat", capabilities: 385},
    ])

    const r = await c.ai.getProfiles()
    assert.ok(r.err === undefined, messages(r.err))
    assert.ok(r.v[0].length === 1)
    assert.ok(r.v[0][0].name === "Chat")

    assert.ok(a[0].url.pathname === "/api/2.0/ai/profiles/list")
  })

  void test("starts vectorization answered with null", async() => {
    const [c, a] = setupClient(200, null)

    const r = await c.ai.startVectorization({files: [1, 2]})
    assert.ok(r.err === undefined, messages(r.err))

    assert.ok(a[0].method === "POST")
    assert.ok(a[0].url.pathname === "/api/2.0/ai/vectorization/tasks")
    assert.deepEqual(a[0].body, {files: [1, 2]})
  })

  void test("reports the error message of the ai service", async() => {
    const [c] = setupClient(403, {error: "The caller may not vectorize the file"})

    const r = await c.ai.startVectorization({files: [1]})
    assert.ok(r.err !== undefined)
    assert.match(messages(r.err), /403 The caller may not vectorize the file/)
  })

  void test("reports the provider message of the ai service", async() => {
    const [c] = setupClient(402, {error: "Payment required", code: "payment_required", providerMessage: "Out of credits"})

    const r = await c.ai.getProfiles()
    assert.ok(r.err !== undefined)
    assert.match(messages(r.err), /402 Payment required: Out of credits/)
  })

  void test("reports a bare forbidden of the ai feature filter", async() => {
    const [c] = setupClient(403)

    const r = await c.files.getAiProjectSources(12)
    assert.ok(r.err !== undefined)
    assert.match(messages(r.err), /403/)
  })
})

type Route = {
  method: string
  path: string
  status: number
  body?: unknown
}

type Served = {
  method: string
  url: URL
  body: unknown
}

async function callTool(t: test.TestContext, routes: Route[], name: string, args: Record<string, unknown>): Promise<[types.CallToolResult, Served[]]> {
  const [hs, ha] = await setupHttp(t)

  const served: Served[] = []

  const hl: AsyncRequestListener = async(req, res) => {
    assert.ok(req.url && req.method)

    const url = new URL(req.url, "http://localhost/")

    let body: unknown
    const d = await readHttpData(req)
    assert.ok(d.err === undefined)
    const t = Buffer.concat(d.v).toString("utf8")
    if (t !== "") {
      body = JSON.parse(t)
    }

    served.push({method: req.method, url, body})

    const rt = routes.find((x) => x.method === req.method && x.path === url.pathname)
    assert.ok(rt, `unexpected request ${req.method} ${url.pathname}`)

    if (rt.body === undefined) {
      res.statusCode = rt.status
      res.end()
      return
    }

    const sr = await sendJson(res, rt.status, rt.body)
    assert.ok(sr.err === undefined)
  }

  const hp = onRequest(t, hs, hl)

  const tf = async(): Promise<types.CallToolResult> => {
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

    const cr = await r.safeAsync(cl.callTool.bind(cl), {name, arguments: args})
    assert.ok(cr.err === undefined, String(cr.err))

    return cr.v as types.CallToolResult
  }

  const v = await Promise.race([hp.then(() => undefined), tf()])
  assert.ok(v)

  return [v, served]
}

function text(v: types.CallToolResult): string {
  const c = v.content[0]
  assert.ok(c.type === "text")
  return c.text
}

const profileId = "019ed117-6bd3-7861-ab75-44f72d17d724"

void test.suite("ai rooms tools", () => {
  void test("lists the ai rooms toolset", async(t) => {
    const so: SetupMcpOptions = {
      transport: "stdio",
      host: "",
      port: 0,
      env: {
        DOCSPACE_BASE_URL: "http://localhost/",
        DOCSPACE_API_KEY: "xxx",
        DOCSPACE_TOOLSETS: "ai_rooms",
      },
    }

    const cl = await setupMcp(t, so)

    const lr = await r.safeAsync(cl.listTools.bind(cl))
    assert.ok(lr.err === undefined)

    assert.deepEqual(lr.v.tools.map((x) => x.name).sort(), [
      "create_ai_room",
      "delete_ai_room",
      "get_ai_config",
      "get_ai_profiles",
      "get_ai_project_model",
      "get_ai_project_sources",
      "get_ai_rooms_folder",
      "get_ai_skills",
      "link_ai_project_sources",
      "retry_vectorization",
      "set_ai_project_model",
      "unlink_ai_project_sources",
    ])
  })

  void test("gets the ai config flags", async(t) => {
    const [v] = await callTool(t, [
      {method: "GET", path: "/api/2.0/ai/config", status: 200, body: envelope({aiReady: true, vectorizationEnabled: false, embeddingModel: "x"})},
    ], "get_ai_config", {})

    assert.ok(!v.isError, text(v))
    assert.deepEqual(v.structuredContent, {aiReady: true, vectorizationEnabled: false})
  })

  void test("gets only the chat profiles", async(t) => {
    const [v] = await callTool(t, [
      {method: "GET", path: "/api/2.0/ai/profiles/list", status: 200, body: [
        {id: "a", name: "Chat", providerType: "onlyoffice", baseUrl: "x", modelId: "chat", capabilities: 385, canUseTool: true},
        {id: "b", name: "Image", providerType: "onlyoffice", baseUrl: "x", modelId: "image", capabilities: 2, canUseTool: false},
        {id: "c", name: "Legacy", providerType: "openai", baseUrl: "x", modelId: "legacy"},
      ]},
    ], "get_ai_profiles", {})

    assert.ok(!v.isError, text(v))
    assert.deepEqual(v.structuredContent, {
      profiles: [
        {id: "a", name: "Chat", providerType: "onlyoffice", modelId: "chat", tools: true, vision: true},
        {id: "c", name: "Legacy", providerType: "openai", modelId: "legacy", tools: false, vision: false},
      ],
    })
  })

  void test("gets the ai rooms section", async(t) => {
    const [v, s] = await callTool(t, [
      {method: "GET", path: "/api/2.0/files/rooms", status: 200, body: envelope({files: [], folders: [{id: 12, roomType: 12}], current: {id: 1}, total: 1})},
    ], "get_ai_rooms_folder", {filters: {type: [12], fields: []}})

    assert.ok(!v.isError, text(v))
    assert.ok(s[0].url.searchParams.get("searchArea") === "AiHub")
    assert.deepEqual(s[0].url.searchParams.getAll("type"), ["12"])
  })

  void test("creates an ai room", async(t) => {
    const [v, s] = await callTool(t, [
      {method: "POST", path: "/api/2.0/files/rooms", status: 200, body: envelope({id: 11, title: "Docs", roomType: 11})},
    ], "create_ai_room", {title: "Docs", roomType: 11, color: "70E096", filters: {fields: []}})

    assert.ok(!v.isError, text(v))
    assert.deepEqual(s[0].body, {title: "Docs", roomType: 11, color: "70E096"})
  })

  void test("explains a refused knowledge room", async(t) => {
    const [v] = await callTool(t, [
      {method: "POST", path: "/api/2.0/files/rooms", status: 403},
    ], "create_ai_room", {title: "Docs", roomType: 11, filters: {fields: []}})

    assert.ok(v.isError)
    assert.match(text(v), /only while vectorization is enabled/)
  })

  void test("refuses ai room types in create_room", async(t) => {
    const [v, s] = await callTool(t, [], "create_room", {title: "Docs", roomType: 11, filters: {fields: []}})

    assert.ok(v.isError)
    assert.ok(s.length === 0)
  })

  void test("deletes an ai room", async(t) => {
    const [v, s] = await callTool(t, [
      {method: "GET", path: "/api/2.0/files/rooms/12", status: 200, body: envelope({id: 12, roomType: 12})},
      {method: "DELETE", path: "/api/2.0/files/rooms/12", status: 200, body: envelope({id: "op", progress: 0, finished: false})},
      {method: "GET", path: "/api/2.0/files/fileops", status: 200, body: envelope([{id: "op", progress: 100, finished: true, processed: "1"}])},
    ], "delete_ai_room", {roomId: 12})

    assert.ok(!v.isError, text(v))
    assert.ok(text(v) === "Room deleted.")
    assert.deepEqual(s.slice(0, 2).map((x) => x.method), ["GET", "DELETE"])
    assert.deepEqual(s[1].body, {deleteAfter: false})
  })

  void test("refuses to delete a room that is not an ai room", async(t) => {
    const [v, s] = await callTool(t, [
      {method: "GET", path: "/api/2.0/files/rooms/6", status: 200, body: envelope({id: 6, roomType: 6})},
    ], "delete_ai_room", {roomId: 6})

    assert.ok(v.isError)
    assert.match(text(v), /not an AI room/)
    assert.deepEqual(s.map((x) => x.method), ["GET"])
  })

  for (const [tool, method, reply] of [
    ["link_ai_project_sources", "POST", "Rooms linked."],
    ["unlink_ai_project_sources", "DELETE", "Rooms unlinked."],
  ] as const) {
    void test(`${tool} answered with no content`, async(t) => {
      const [v, s] = await callTool(t, [
        {method, path: "/api/2.0/files/rooms/12/sources", status: 204},
      ], tool, {roomId: 12, roomIds: [10, 11]})

      assert.ok(!v.isError, text(v))
      assert.ok(text(v) === reply)
      assert.deepEqual(s[0].body, {roomIds: [10, 11]})
    })
  }

  void test("gets ai project sources", async(t) => {
    const [v] = await callTool(t, [
      {method: "GET", path: "/api/2.0/files/rooms/12/sources", status: 200, body: envelope({instructionsRooms: [{id: 10, title: "I", logo}], knowledgeRooms: []})},
    ], "get_ai_project_sources", {roomId: 12})

    assert.ok(!v.isError, text(v))
  })

  void test("gets ai skills", async(t) => {
    const [v] = await callTool(t, [
      {method: "GET", path: "/api/2.0/files/rooms/12/skills", status: 200, body: envelope({rooms: [{id: 10, title: "I", logo, skills: []}]})},
    ], "get_ai_skills", {roomId: 12})

    assert.ok(!v.isError, text(v))
  })

  void test("gets an ai project model that is not set", async(t) => {
    const [v] = await callTool(t, [
      {method: "GET", path: "/api/2.0/files/rooms/12/model", status: 200, body: envelope({})},
    ], "get_ai_project_model", {roomId: 12})

    assert.ok(!v.isError, text(v))
  })

  void test("sets an ai project model", async(t) => {
    const [v, s] = await callTool(t, [
      {method: "PUT", path: "/api/2.0/files/rooms/12/model", status: 200, body: envelope({profileId})},
    ], "set_ai_project_model", {roomId: 12, profileId})

    assert.ok(!v.isError, text(v))
    assert.deepEqual(s[0].body, {profileId})
  })

  void test("explains a refused ai project model", async(t) => {
    const [v] = await callTool(t, [
      {method: "PUT", path: "/api/2.0/files/rooms/12/model", status: 400},
    ], "set_ai_project_model", {roomId: 12, profileId})

    assert.ok(v.isError)
    assert.match(text(v), /not a chat model/)
  })

  void test("retries vectorization", async(t) => {
    const [v, s] = await callTool(t, [
      {method: "POST", path: "/api/2.0/ai/vectorization/tasks", status: 200, body: null},
    ], "retry_vectorization", {fileIds: [1, 2]})

    assert.ok(!v.isError, text(v))
    assert.deepEqual(s[0].body, {files: [1, 2]})
  })

  void test("says that vectorized files are skipped", async(t) => {
    const [v] = await callTool(t, [
      {method: "POST", path: "/api/2.0/ai/vectorization/tasks", status: 200, body: {response: null, count: 0, status: 0, statusCode: 200}},
    ], "retry_vectorization", {fileIds: [1]})

    assert.ok(!v.isError, text(v))
    assert.match(text(v), /already vectorized or being vectorized are skipped/)
  })

  void test("explains a file that was never queued for vectorization", async(t) => {
    const [v] = await callTool(t, [
      {method: "POST", path: "/api/2.0/ai/vectorization/tasks", status: 403, body: {error: "Forbidden"}},
    ], "retry_vectorization", {fileIds: [1]})

    assert.ok(v.isError)
    assert.match(text(v), /queued for vectorization before/)
  })

  void test("explains a file that does not exist", async(t) => {
    const [v] = await callTool(t, [
      {method: "POST", path: "/api/2.0/ai/vectorization/tasks", status: 404, body: {error: "Not Found"}},
    ], "retry_vectorization", {fileIds: [1]})

    assert.ok(v.isError)
    assert.match(text(v), /One of the files does not exist./)
    assert.doesNotMatch(text(v), /queued/)
  })

  for (const [roomType, levels] of [[10, [2, 9, 10, 11]], [11, [2, 9, 11]], [12, [2, 9]]] as const) {
    void test(`lists the access levels of room type ${roomType}`, async(t) => {
      const [v] = await callTool(t, [
        {method: "GET", path: "/api/2.0/files/rooms/1", status: 200, body: envelope({id: 1, roomType})},
      ], "get_room_access_levels", {roomId: 1})

      assert.ok(!v.isError, text(v))
      const j = JSON.parse(text(v)) as {anyOf: {const: number}[]}
      assert.deepEqual(j.anyOf.map((x) => x.const), levels)
    })
  }
})
