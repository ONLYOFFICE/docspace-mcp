/**
 * @module test
 */

import assert from "node:assert/strict"
import test from "node:test"
import * as types from "@modelcontextprotocol/sdk/types.js"
import * as core from "../lib/api/core.ts"
import * as r from "../lib/util/result.ts"
import type {AsyncRequestListener, SetupMcpOptions} from "./util.ts"
import {onRequest, sendJson, setupHttp, setupMcp} from "./util.ts"

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
