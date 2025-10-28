/**
 * (c) Copyright Ascensio System SIA 2025
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @license
 */

import * as z from "zod"
import * as meta from "../../lib/meta.ts"
import * as result from "../../lib/util/result.ts"
import type * as types from "../../lib/util/types.ts"
import * as zod from "../../lib/util/zod.ts"
import * as tools from "./tools.ts"
import * as transports from "./transports.ts"

export interface Config {
	internal: boolean
	mcp: Mcp
	api: Api
	server: Server
	request: Request
}

export interface Mcp {
	transport: transports.Transport
	dynamic: boolean
	toolsets: string[]
	tools: string[]
	enabledTools: string[]
	disabledTools: string[]
	session: McpSession
}

export interface McpSession {
	ttl: number
	interval: number
}

export interface Api {
	userAgent: string
	shared: ApiShared
}

export interface ApiShared {
	baseUrl: string
	authorization: string
	apiKey: string
	pat: string
	username: string
	password: string
}

export interface Server {
	host: string
	port: number
	proxy: Proxy
	cors: Cors
	rateLimits: RateLimits
}

export interface Proxy {
	hops: number
}

export interface Cors {
	mcp: CorsItem
}

export interface CorsItem {
	origin: string[]
	maxAge: number
}

export interface RateLimits {
	mcp: RateLimit
}

export interface RateLimit {
	capacity: number
	window: number
}

export interface Request {
	query: boolean
	authorizationHeader: boolean
	headerPrefix: string
}

export const ConfigSchema = z.
	object({
		DOCSPACE_INTERNAL: z.
			string().
			default("0").
			transform(zod.envBoolean()),

		DOCSPACE_TRANSPORT: z.
			string().
			default("stdio").
			transform(zod.envUnion([...transports.availableTransports])),

		DOCSPACE_DYNAMIC: z.
			string().
			default("0").
			transform(zod.envBoolean()),

		DOCSPACE_TOOLSETS: z.
			string().
			default("all").
			transform(zod.envOptions([...tools.availableToolsets])),

		DOCSPACE_ENABLED_TOOLS: z.
			string().
			default("").
			transform(zod.envOptions([...tools.availableTools])),

		DOCSPACE_DISABLED_TOOLS: z.
			string().
			default("").
			transform(zod.envOptions([...tools.availableTools])),

		DOCSPACE_SESSION_TTL: z.
			string().
			default("28800000"). // 8 hours
			transform(zod.envNumber()).
			pipe(z.number().min(0)),

		DOCSPACE_SESSION_INTERVAL: z.
			string().
			default("240000"). // 4 minutes
			transform(zod.envNumber()).
			pipe(z.number().min(0)),

		DOCSPACE_USER_AGENT: z.
			string().
			trim().
			default(`${meta.name} v${meta.version}`),

		DOCSPACE_BASE_URL: z.
			string().
			default("").
			transform(zod.envBaseUrl()),

		DOCSPACE_AUTHORIZATION: z.
			string().
			trim().
			default(""),

		DOCSPACE_API_KEY: z.
			string().
			trim().
			default(""),

		DOCSPACE_AUTH_TOKEN: z.
			string().
			trim().
			default(""),

		DOCSPACE_USERNAME: z.
			string().
			trim().
			default(""),

		DOCSPACE_PASSWORD: z.
			string().
			trim().
			default(""),

		DOCSPACE_HOST: z.
			string().
			trim().
			default("127.0.0.1"),

		DOCSPACE_PORT: z.
			string().
			default("8080").
			transform(zod.envNumber()).
			pipe(z.number().min(0).max(65535)),

		DOCSPACE_PROXY_HOPS: z.
			string().
			default("0").
			transform(zod.envNumber()).
			pipe(z.number().min(0)),

		DOCSPACE_SERVER_CORS_MCP_ORIGIN: z.
			string().
			default("*").
			transform(zod.envList()),

		DOCSPACE_SERVER_CORS_MCP_MAX_AGE: z.
			string().
			default("86400000"). // 1 day
			transform(zod.envNumber()).
			pipe(z.number().min(0)),

		DOCSPACE_SERVER_RATE_LIMITS_MCP_CAPACITY: z.
			string().
			default("1000").
			transform(zod.envNumber()).
			pipe(z.number().min(0)),

		DOCSPACE_SERVER_RATE_LIMITS_MCP_WINDOW: z.
			string().
			default("1000"). // 1 second
			transform(zod.envNumber()).
			pipe(z.number().min(0)),

		DOCSPACE_REQUEST_QUERY: z.
			string().
			default("1").
			transform(zod.envBoolean()),

		DOCSPACE_REQUEST_AUTHORIZATION_HEADER: z.
			string().
			default("1").
			transform(zod.envBoolean()),

		DOCSPACE_REQUEST_HEADER_PREFIX: z.
			string().
			trim().
			toLowerCase().
			default("x-mcp-"),
	}).
	transform((o) => {
		let c: Config = {
			internal: o.DOCSPACE_INTERNAL,
			mcp: {
				transport: o.DOCSPACE_TRANSPORT,
				dynamic: o.DOCSPACE_DYNAMIC,
				toolsets: o.DOCSPACE_TOOLSETS,
				tools: [],
				enabledTools: o.DOCSPACE_ENABLED_TOOLS,
				disabledTools: o.DOCSPACE_DISABLED_TOOLS,
				session: {
					ttl: o.DOCSPACE_SESSION_TTL,
					interval: o.DOCSPACE_SESSION_INTERVAL,
				},
			},
			api: {
				userAgent: o.DOCSPACE_USER_AGENT,
				shared: {
					baseUrl: o.DOCSPACE_BASE_URL,
					authorization: o.DOCSPACE_AUTHORIZATION,
					apiKey: o.DOCSPACE_API_KEY,
					pat: o.DOCSPACE_AUTH_TOKEN,
					username: o.DOCSPACE_USERNAME,
					password: o.DOCSPACE_PASSWORD,
				},
			},
			server: {
				host: o.DOCSPACE_HOST,
				port: o.DOCSPACE_PORT,
				proxy: {
					hops: o.DOCSPACE_PROXY_HOPS,
				},
				cors: {
					mcp: {
						origin: o.DOCSPACE_SERVER_CORS_MCP_ORIGIN,
						maxAge: o.DOCSPACE_SERVER_CORS_MCP_MAX_AGE,
					},
				},
				rateLimits: {
					mcp: {
						capacity: o.DOCSPACE_SERVER_RATE_LIMITS_MCP_CAPACITY,
						window: o.DOCSPACE_SERVER_RATE_LIMITS_MCP_WINDOW,
					},
				},
			},
			request: {
				query: o.DOCSPACE_REQUEST_QUERY,
				authorizationHeader: o.DOCSPACE_REQUEST_AUTHORIZATION_HEADER,
				headerPrefix: o.DOCSPACE_REQUEST_HEADER_PREFIX,
			},
		}

		c.mcp.toolsets = tools.normalizeToolsets(c.mcp.toolsets)

		;[c.mcp.toolsets, c.mcp.tools] = tools.resolveToolsetsAndTools(
			c.mcp.toolsets,
			c.mcp.enabledTools,
			c.mcp.disabledTools,
		)

		if (c.internal) {
			c = {
				internal: c.internal,
				mcp: {
					transport: "streamable-http",
					dynamic: c.mcp.dynamic,
					toolsets: c.mcp.toolsets,
					tools: c.mcp.tools,
					enabledTools: c.mcp.enabledTools,
					disabledTools: c.mcp.disabledTools,
					session: c.mcp.session,
				},
				api: {
					userAgent: c.api.userAgent,
					shared: {
						baseUrl: "",
						authorization: "",
						apiKey: "",
						pat: "",
						username: "",
						password: "",
					},
				},
				server: {
					host: c.server.host,
					port: c.server.port,
					proxy: {
						hops: 0,
					},
					cors: {
						mcp: {
							origin: [],
							maxAge: 0,
						},
					},
					rateLimits: {
						mcp: {
							capacity: 0,
							window: 0,
						},
					},
				},
				request: {
					query: false,
					authorizationHeader: false,
					headerPrefix: "",
				},
			}
		}

		if (c.mcp.transport === "stdio") {
			c = {
				internal: c.internal,
				mcp: c.mcp,
				api: {
					userAgent: c.api.userAgent,
					shared: c.api.shared,
				},
				server: {
					host: "",
					port: 0,
					proxy: {
						hops: 0,
					},
					cors: {
						mcp: {
							origin: [],
							maxAge: 0,
						},
					},
					rateLimits: {
						mcp: {
							capacity: 0,
							window: 0,
						},
					},
				},
				request: {
					query: false,
					authorizationHeader: false,
					headerPrefix: "",
				},
			}
		}

		return c
	}).
	superRefine((o, ctx) => {
		if (o.mcp.toolsets.length === 0) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "No toolsets left",
			})
		}

		if (o.mcp.tools.length === 0) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "No tools left",
			})
		}

		if (o.mcp.transport === "stdio") {
			let a = Boolean(o.api.shared.authorization)
			let b = Boolean(o.api.shared.apiKey)
			let c = Boolean(o.api.shared.pat)
			let d = Boolean(o.api.shared.username) && Boolean(o.api.shared.password)
			let u = Number(a) + Number(b) + Number(c) + Number(d)

			if (u === 0) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message: "Expected at least one of Authorization header, API key, PAT, or (username and password) to be set for stdio transport",
				})
			}

			if (u !== 0 && u !== 1) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message: "Expected only one of Authorization header, API key, PAT, or (username and password) to be set for stdio transport",
				})
			}

			if ((a || b || c || d) && !o.api.shared.baseUrl) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message: "API base URL is required for stdio transport with Authorization header, API key, PAT, or (username and password)",
				})
			}
		}

		if (
			o.mcp.transport === "sse" ||
			o.mcp.transport === "streamable-http" ||
			o.mcp.transport === "http"
		) {
			let t = ""
			switch (o.mcp.transport) {
			case "sse":
				t = "SSE"
				break
			case "streamable-http":
				t = "Streamable HTTP"
				break
			case "http":
				t = "HTTP"
				break
			}

			let a = Boolean(o.api.shared.authorization)
			let b = Boolean(o.api.shared.apiKey)
			let c = Boolean(o.api.shared.pat)
			let d = Boolean(o.api.shared.username) && Boolean(o.api.shared.password)
			let u = Number(a) + Number(b) + Number(c) + Number(d)

			if (u !== 0 && u !== 1) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message: `Expected only one of Authorization header, API key, PAT, or (username and password) to be set for ${t} transport`,
				})
			}

			if ((a || b || c || d) && !o.api.shared.baseUrl) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message: `API base URL is required for ${t} transport with Authorization header, API key, PAT, or (username and password)`,
				})
			}

			if (!o.server.host) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message: `Server host is required for ${t} transport`,
				})
			}
		}
	})

export function load(): result.Result<Config, Error> {
	let o = ConfigSchema.safeParse(process.env)
	if (o.error) {
		return result.error(new Error("Parsing environment variables", {cause: o.error}))
	}
	return result.ok(o.data)
}

export function format(c: Config): object {
	let o: types.RecursivePartial<Config> = {}

	let mcp = formatMcp(c.mcp)
	if (Object.keys(mcp).length !== 0) {
		o.mcp = mcp
	}

	let api = formatApi(c.api)
	if (Object.keys(api).length !== 0) {
		o.api = api
	}

	let server = formatServer(c.server)
	if (Object.keys(server).length !== 0) {
		o.server = server
	}

	let request = formatRequest(c.request)
	if (Object.keys(request).length !== 0) {
		o.request = request
	}

	return o
}

function formatMcp(c: Mcp): types.RecursivePartial<Mcp> {
	let o: types.RecursivePartial<Mcp> = {}

	if (c.transport) {
		o.transport = c.transport
	}

	if (c.dynamic) {
		o.dynamic = c.dynamic
	}

	if (c.toolsets.length !== 0) {
		o.toolsets = c.toolsets
	}

	if (c.tools.length !== 0) {
		o.tools = c.tools
	}

	let session = formatMcpSession(c.session)
	if (Object.keys(session).length !== 0) {
		o.session = session
	}

	return o
}

function formatMcpSession(c: McpSession): types.RecursivePartial<McpSession> {
	let o: types.RecursivePartial<McpSession> = {}

	if (c.ttl) {
		o.ttl = c.ttl
	}

	if (c.interval) {
		o.interval = c.interval
	}

	return o
}

function formatApi(c: Api): types.RecursivePartial<Api> {
	let o: types.RecursivePartial<Api> = {}

	if (c.userAgent) {
		o.userAgent = c.userAgent
	}

	let shared = formatApiShared(c.shared)
	if (Object.keys(shared).length !== 0) {
		o.shared = shared
	}

	return o
}

function formatApiShared(c: ApiShared): types.RecursivePartial<ApiShared> {
	let o: types.RecursivePartial<ApiShared> = {}

	if (c.baseUrl) {
		o.baseUrl = c.baseUrl
	}

	if (c.authorization) {
		o.authorization = "***"
	}

	if (c.apiKey) {
		o.apiKey = "***"
	}

	if (c.pat) {
		o.pat = "***"
	}

	if (c.username) {
		o.username = "***"
	}

	if (c.password) {
		o.password = "***"
	}

	return o
}

function formatServer(c: Server): types.RecursivePartial<Server> {
	let o: types.RecursivePartial<Server> = {}

	if (c.host) {
		o.host = c.host
	}

	if (c.port) {
		o.port = c.port
	}

	let proxy = formatProxy(c.proxy)
	if (Object.keys(proxy).length !== 0) {
		o.proxy = proxy
	}

	let cors = formatCors(c.cors)
	if (Object.keys(cors).length !== 0) {
		o.cors = cors
	}

	let rateLimits = formatRateLimits(c.rateLimits)
	if (Object.keys(rateLimits).length !== 0) {
		o.rateLimits = rateLimits
	}

	return o
}

function formatProxy(c: Proxy): types.RecursivePartial<Proxy> {
	let o: types.RecursivePartial<Proxy> = {}

	if (c.hops) {
		o.hops = c.hops
	}

	return o
}

function formatCors(c: Cors): types.RecursivePartial<Cors> {
	let o: types.RecursivePartial<Cors> = {}

	let mcp = formatCorsItem(c.mcp)
	if (Object.keys(mcp).length !== 0) {
		o.mcp = mcp
	}

	return o
}

function formatCorsItem(c: CorsItem): types.RecursivePartial<CorsItem> {
	let o: types.RecursivePartial<CorsItem> = {}

	if (c.origin) {
		o.origin = c.origin
	}

	if (c.maxAge) {
		o.maxAge = c.maxAge
	}

	return o
}

function formatRateLimits(c: RateLimits): types.RecursivePartial<RateLimits> {
	let o: types.RecursivePartial<RateLimits> = {}

	let mcp = formatRateLimit(c.mcp)
	if (Object.keys(mcp).length !== 0) {
		o.mcp = mcp
	}

	return o
}

function formatRateLimit(c: RateLimit): types.RecursivePartial<RateLimit> {
	let o: types.RecursivePartial<RateLimit> = {}

	if (c.capacity) {
		o.capacity = c.capacity
	}

	if (c.window) {
		o.window = c.window
	}

	return o
}

function formatRequest(c: Request): types.RecursivePartial<Request> {
	let o: types.RecursivePartial<Request> = {}

	if (c.authorizationHeader) {
		o.authorizationHeader = c.authorizationHeader
	}

	if (c.headerPrefix) {
		o.headerPrefix = c.headerPrefix
	}

	return o
}
