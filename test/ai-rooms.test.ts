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
