#!/usr/bin/env node

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

/* eslint-disable typescript/consistent-type-definitions */

import * as server from "@modelcontextprotocol/sdk/server/index.js"
import * as stdio from "@modelcontextprotocol/sdk/server/stdio.js"
import type * as types from "@modelcontextprotocol/sdk/types.js"
import express from "express"
import * as z from "zod"
import * as api from "../lib/api.ts"
import * as auth from "../lib/auth.ts"
import * as mcp from "../lib/mcp.ts"
import * as meta from "../lib/meta.ts"
import * as settings from "../lib/settings.ts"
import * as context from "../lib/util/context.ts"
import * as errors from "../lib/util/errors.ts"
import * as utilExpress from "../lib/util/express.ts"
import * as utilFetch from "../lib/util/fetch.ts"
import * as utilLogger from "../lib/util/logger.ts"
import * as utilMcp from "../lib/util/mcp.ts"
import * as r from "../lib/util/result.ts"
import * as zod from "../lib/util/zod.ts"

type Transport =
	"stdio" |
	"sse" |
	"streamable-http" |
	"http"

const availableTransports: Transport[] = [
	"stdio",
	"sse",
	"streamable-http",
	"http",
]

const availableToolsets = (() => {
	let a: string[] = []
	for (let s of mcp.toolsetInfos) {
		a.push(s.name)
	}
	return a
})()

const availableTools = (() => {
	let a: string[] = []
	for (let s of mcp.toolsetInfos) {
		for (let t of s.tools) {
			a.push(t.name)
		}
	}
	return a
})()

const ConfigSchema = z.
	object({
		DOCSPACE_INTERNAL: z.
			string().
			default("0").
			transform(zod.envBoolean()),
		DOCSPACE_TRANSPORT: z.
			string().
			default("stdio").
			transform(zod.envUnion(availableTransports)),
		DOCSPACE_DYNAMIC: z.
			string().
			default("0").
			transform(zod.envBoolean()),
		DOCSPACE_TOOLSETS: z.
			string().
			default("all").
			transform(zod.envOptions(["all", ...availableToolsets])).
			transform((o) => {
				if (o.includes("all")) {
					o = [...availableToolsets]
				}
				return o
			}),
		DOCSPACE_ENABLED_TOOLS: z.
			string().
			default("").
			transform(zod.envOptions(availableTools)),
		DOCSPACE_DISABLED_TOOLS: z.
			string().
			default("").
			transform(zod.envOptions(availableTools)),
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
	transform((o) => ({
		internal: o.DOCSPACE_INTERNAL,
		mcp: {
			transport: o.DOCSPACE_TRANSPORT,
			dynamic: o.DOCSPACE_DYNAMIC,
			toolsets: o.DOCSPACE_TOOLSETS,
			tools: [] as string[],
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
	}))

type Config = z.infer<typeof ConfigSchema>

type Start = {
	promise: Promise<r.Result<void, Error>>
	cleanup(): Promise<r.Result<void, Error>>
}

async function main(): Promise<void> {
	let l = new utilLogger.VanillaLogger(process.stdout)

	try {
		let c = loadConfig()

		if (c.err || c.v.mcp.transport === "stdio") {
			l.mute()
		}

		if (c.err) {
			l.error("Loading config", {err: c.err})
		} else {
			l.info("Loaded config", formatConfig(c.v))
		}

		let s: r.Result<Start, Error> | undefined

		if (c.err || c.v.mcp.transport === "stdio") {
			s = startStdio(c)
		} else {
			s = startHttp(c.v, l)
		}

		if (s.err) {
			l.error("Starting server", {err: s.err})
			return
		}

		for (let e of ["SIGTERM", "SIGINT"]) {
			process.on(e, () => {
				void (async() => {
					l.info(`Received ${e}, shutting down`)

					let c = await s.v.cleanup()
					if (c.err) {
						l.error("Cleaning up", {err: c.err})
					}

					if (c.err) {
						l.error("Shut down with an error")
						process.exit(1)
					}

					l.info("Shut down successfully")
					process.exit(0)
				})()
			})
		}

		let p = await s.v.promise
		if (p.err) {
			l.error("Server failed to start", {err: p.err})

			let c = await s.v.cleanup()
			if (c.err) {
				l.error("Cleaning up", {err: c.err})
			}

			l.error("Shut down with an error")
			process.exit(1)
		}
	} catch (err) {
		l.error("Executing main", {err})
		process.exit(1)
	}
}

function loadConfig(): r.Result<Config, Error> {
	let p = ConfigSchema.safeParse(process.env)
	if (p.error) {
		return r.error(new Error("Parsing environment variables", {cause: p.error}))
	}

	if (p.data.internal) {
		p.data = {
			internal: p.data.internal,
			mcp: {
				transport: "streamable-http",
				dynamic: p.data.mcp.dynamic,
				toolsets: p.data.mcp.toolsets,
				tools: p.data.mcp.tools,
				enabledTools: p.data.mcp.enabledTools,
				disabledTools: p.data.mcp.disabledTools,
				session: p.data.mcp.session,
			},
			api: {
				userAgent: p.data.api.userAgent,
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
				host: p.data.server.host,
				port: p.data.server.port,
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

	if (p.data.mcp.transport === "stdio") {
		p.data = {
			internal: p.data.internal,
			mcp: p.data.mcp,
			api: {
				userAgent: p.data.api.userAgent,
				shared: p.data.api.shared,
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

	let to: settings.ResolveToolsOptions = {
		toolsets: p.data.mcp.toolsets,
		enabledTools: p.data.mcp.enabledTools,
		disabledTools: p.data.mcp.disabledTools,
	}

	let t = settings.resolveTools(to)

	p.data.mcp.toolsets = t.toolsets
	p.data.mcp.tools = t.tools

	let errs: Error[] = []

	if (p.data.mcp.toolsets.length === 0) {
		errs.push(new Error("No toolsets left"))
	}

	if (p.data.mcp.tools.length === 0) {
		errs.push(new Error("No tools left"))
	}

	if (p.data.mcp.transport === "stdio") {
		let a = Boolean(p.data.api.shared.authorization)
		let b = Boolean(p.data.api.shared.apiKey)
		let c = Boolean(p.data.api.shared.pat)
		let d = Boolean(p.data.api.shared.username) && Boolean(p.data.api.shared.password)
		let u = Number(a) + Number(b) + Number(c) + Number(d)

		if (u === 0) {
			errs.push(new Error("Expected at least one of Authorization header, API key, PAT, or (username and password) to be set for stdio transport"))
		}

		if (u !== 0 && u !== 1) {
			errs.push(new Error("Expected only one of Authorization header, API key, PAT, or (username and password) to be set for stdio transport"))
		}

		if ((a || b || c || d) && !p.data.api.shared.baseUrl) {
			errs.push(new Error("API base URL is required for stdio transport with Authorization header, API key, PAT, or (username and password)"))
		}
	}

	if (
		p.data.mcp.transport === "sse" ||
		p.data.mcp.transport === "streamable-http" ||
		p.data.mcp.transport === "http"
	) {
		let t = ""
		switch (p.data.mcp.transport) {
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

		let a = Boolean(p.data.api.shared.authorization)
		let b = Boolean(p.data.api.shared.apiKey)
		let c = Boolean(p.data.api.shared.pat)
		let d = Boolean(p.data.api.shared.username) && Boolean(p.data.api.shared.password)
		let u = Number(a) + Number(b) + Number(c) + Number(d)

		if (u !== 0 && u !== 1) {
			errs.push(new Error(`Expected only one of Authorization header, API key, PAT, or (username and password) to be set for ${t} transport`))
		}

		if ((a || b || c || d) && !p.data.api.shared.baseUrl) {
			errs.push(new Error(`API base URL is required for ${t} transport with Authorization header, API key, PAT, or (username and password)`))
		}

		if (!p.data.server.host) {
			errs.push(new Error(`Server host is required for ${t} transport`))
		}
	}

	if (errs.length !== 0) {
		return r.error(new errors.Errors({cause: errs}))
	}

	return r.ok(p.data)
}

function formatConfig(c: Config): object {
	let m = "***"

	// eslint-disable-next-line unicorn/prefer-set-has
	let s: string[] = [
		"root.api.shared.authorization",
		"root.api.shared.apiKey",
		"root.api.shared.pat",
		"root.api.shared.username",
		"root.api.shared.password",
	]

	let h = (v: unknown, p: string): unknown => {
		if (!v) {
			return
		}

		if (Array.isArray(v)) {
			if (v.length === 0) {
				return
			}

			return v
		}

		if (typeof v === "object") {
			if (Object.keys(v).length === 0) {
				return
			}

			let o: Record<string, unknown> = {}

			for (let [x, y] of Object.entries(v)) {
				let n = h(y, `${p}.${x}`)

				if (n) {
					o[x] = n
				}
			}

			if (Object.keys(o).length === 0) {
				return
			}

			return o
		}

		if (s.includes(p)) {
			return m
		}

		return v
	}

	let o = h(c, "root")

	return o as object
}

function startStdio(config: r.Result<Config, Error>): r.Result<Start, Error> {
	let msc: types.Implementation = {
		name: meta.name,
		version: meta.version,
	}

	let ms = new server.Server(msc)

	let defs: utilMcp.RequestDefinition[] | undefined

	if (config.err) {
		defs = mcp.misconfiguredServer(config.err)
	} else {
		let cp: utilLogger.ContextProvider = {
			get() {
				// eslint-disable-next-line unicorn/no-useless-undefined
				return undefined
			},
		}

		let sl = new utilLogger.ServerLogger(cp, ms)

		ms.registerCapabilities({logging: {}})

		let fetch = utilFetch.withLogger(context, sl, globalThis.fetch)

		let cc: api.ClientConfig = {
			userAgent: config.v.api.userAgent,
			baseUrl: config.v.api.shared.baseUrl,
			fetch,
		}

		let c = new api.Client(cc)

		if (config.v.api.shared.authorization) {
			c = c.withAuth(config.v.api.shared.authorization)
		}

		if (config.v.api.shared.apiKey) {
			c = c.withApiKey(config.v.api.shared.apiKey)
		}

		if (config.v.api.shared.pat) {
			c = c.withAuthToken(config.v.api.shared.pat)
		}

		if (config.v.api.shared.username && config.v.api.shared.password) {
			c = c.withBasicAuth(config.v.api.shared.username, config.v.api.shared.password)
		}

		let csc: mcp.ConfiguredServerConfig = {
			client: c,
			resolver: new api.Resolver(c),
			uploader: new api.Uploader(c),
			dynamic: config.v.mcp.dynamic,
			tools: config.v.mcp.tools,
		}

		defs = mcp.configuredServer(csc)
	}

	utilMcp.register(ms, defs)

	let mt = new stdio.StdioServerTransport()

	let promise = new Promise<r.Result<void, Error>>((res) => {
		ms.connect(mt).
			// eslint-disable-next-line promise/prefer-await-to-then
			then(() => {
				res(r.ok())
				return
			}).
			// eslint-disable-next-line promise/prefer-await-to-then
			catch((err: unknown) => {
				res(r.error(new Error("Attaching server", {cause: err})))
			})
	})

	let cleanup = async(): Promise<r.Result<void, Error>> => {
		let c = await r.safeAsync(mt.close.bind(mt))
		if (c.err) {
			return r.error(new Error("Closing transport", {cause: c.err}))
		}
		return r.ok()
	}

	let s: Start = {
		promise,
		cleanup,
	}

	return r.ok(s)
}

function startHttp(config: Config, logger: utilLogger.VanillaLogger): r.Result<Start, Error> {
	let credentialParserRequestHeaders: string[] | undefined
	let credentialParser: auth.AuthManagerCredentialParser | undefined

	if (config.internal) {
		let icp = new auth.InternalCredentialParser()

		credentialParserRequestHeaders = icp.requestHeaders
		credentialParser = icp
	} else {
		let cpc: auth.CredentialParserConfig = {
			queryEnabled: config.request.query,
			headerPrefix: config.request.headerPrefix,
		}

		let cp = new auth.CredentialParser(cpc)

		credentialParserRequestHeaders = cp.requestHeaders
		credentialParser = cp
	}

	let amc: auth.AuthManagerConfig = {
		defaultBaseUrl: config.api.shared.baseUrl,
		defaultAuth: config.api.shared.authorization,
		defaultApiKey: config.api.shared.apiKey,
		defaultPat: config.api.shared.pat,
		defaultUsername: config.api.shared.username,
		defaultPassword: config.api.shared.password,
		oauthEnabled: false,
		headerEnabled: config.request.authorizationHeader,
		oauthAuthTokens: {
			decode() {
				throw new Error("Not implemented")
			},
		},
		oauthHandlerRequestHeaders: [],
		oauthHandlerResponseHeaders: [],
		oauthHandler() {
			throw new Error("Not implemented")
		},
		credentialParserRequestHeaders,
		credentialParser,
	}

	let am = new auth.AuthManager(amc)

	let authHandler = am.handler()

	let spc: settings.SettingsParserConfig = {
		defaultDynamic: config.mcp.dynamic,
		defaultToolsets: config.mcp.toolsets,
		defaultTools: config.mcp.tools,
		queryEnabled: config.request.query,
		headerPrefix: config.request.headerPrefix,
	}

	let sp = new settings.SettingsParser(spc)

	let create = (req: express.Request): r.Result<server.Server, Error> => {
		let s = sp.parse(req)
		if (s.err) {
			return r.error(new Error("Parsing settings", {cause: s.err}))
		}

		let msc: types.Implementation = {
			name: meta.name,
			version: meta.version,
		}

		let ms = new server.Server(msc)

		let sl = new utilLogger.ServerLogger(context, ms)

		ms.registerCapabilities({logging: {}})

		let fetch = utilFetch.withLogger(context, logger, globalThis.fetch)

		fetch = utilFetch.withLogger(context, sl, fetch)

		let cc: api.ClientConfig = {
			userAgent: config.api.userAgent,
			baseUrl: "",
			fetch,
		}

		if (req.oauth) {
			cc.baseUrl = req.oauth.aud
		}

		if (req.auth) {
			cc.baseUrl = req.auth.baseUrl
		}

		let c = new api.Client(cc)

		if (req.oauth) {
			c = c.withAuthToken(req.oauth.token)
		}

		if (req.auth && req.auth.auth) {
			c = c.withAuth(req.auth.auth)
		}

		if (req.auth && req.auth.apiKey) {
			c = c.withApiKey(req.auth.apiKey)
		}

		if (req.auth && req.auth.pat) {
			c = c.withAuthToken(req.auth.pat)
		}

		if (req.auth && req.auth.username && req.auth.password) {
			c = c.withBasicAuth(req.auth.username, req.auth.password)
		}

		let csc: mcp.ConfiguredServerConfig = {
			client: c,
			resolver: new api.Resolver(c),
			uploader: new api.Uploader(c),
			dynamic: s.v.dynamic,
			tools: s.v.tools,
		}

		let defs = mcp.configuredServer(csc)

		utilMcp.register(ms, defs)

		return r.ok(ms)
	}

	let sseSessions: mcp.Sessions | undefined
	let sseRouter: express.Router | undefined

	if (config.mcp.transport === "sse" || config.mcp.transport === "http") {
		let sc: mcp.SessionsConfig = {
			ttl: config.mcp.session.ttl,
		}

		let s = new mcp.Sessions(sc)

		let stc: mcp.SseTransportsConfig = {
			logger,
			sessions: s,
		}

		let st = new mcp.SseTransports(stc)

		let ssc: mcp.SseServerConfig = {
			corsOrigin: config.server.cors.mcp.origin,
			corsMaxAge: config.server.cors.mcp.maxAge,
			corsAllowedHeaders: [
				...am.requestHeaders,
				...sp.requestHeaders,
			],
			corsExposedHeaders: [
				...am.responseHeaders,
			],
			rateLimitCapacity: config.server.rateLimits.mcp.capacity,
			rateLimitWindow: config.server.rateLimits.mcp.window,
			handlers: [
				authHandler,
			],
			servers: {
				create,
			},
			transports: st,
		}

		let ss = new mcp.SseServer(ssc)

		sseSessions = s
		sseRouter = ss.router()
	}

	let streamableSessions: mcp.Sessions | undefined
	let streamableRouter: express.Router | undefined

	if (config.mcp.transport === "streamable-http" || config.mcp.transport === "http") {
		let sc: mcp.SessionsConfig = {
			ttl: config.mcp.session.ttl,
		}

		let s = new mcp.Sessions(sc)

		let stc: mcp.StreamableTransportsConfig = {
			logger,
			sessions: s,
		}

		let st = new mcp.StreamableTransports(stc)

		let ssc: mcp.StreamableServerConfig = {
			corsOrigin: config.server.cors.mcp.origin,
			corsMaxAge: config.server.cors.mcp.maxAge,
			corsAllowedHeaders: [
				...am.requestHeaders,
				...sp.requestHeaders,
			],
			corsExposedHeaders: [
				...am.responseHeaders,
			],
			rateLimitCapacity: config.server.rateLimits.mcp.capacity,
			rateLimitWindow: config.server.rateLimits.mcp.window,
			handlers: [
				authHandler,
			],
			servers: {
				create,
			},
			transports: st,
		}

		let ss = new mcp.StreamableServer(ssc)

		streamableSessions = s
		streamableRouter = ss.router()
	}

	let e = express()

	e.disable("etag")
	e.disable("x-powered-by")
	e.set("json spaces", 2)

	if (config.server.proxy.hops) {
		e.set("trust proxy", config.server.proxy.hops)
	}

	e.use(utilExpress.context(context))
	e.use(utilExpress.logger(context, logger))

	if (sseRouter) {
		e.use(sseRouter)
	}

	if (streamableRouter) {
		e.use(streamableRouter)
	}

	e.use((_, res) => {
		let err = new errors.JsonError("Not Found")
		res.status(404)
		res.json(err.toObject())
	})

	let cleanupSse: (() => Promise<r.Result<void, Error>>) | undefined

	if (sseSessions) {
		let ac = new AbortController()
		let wp = sseSessions.watch(ac.signal, config.mcp.session.interval)

		cleanupSse = async() => {
			if (!ac.signal.aborted) {
				let errs: Error[] = []

				ac.abort("Cleaning up")

				let err = await wp
				if (err && !errors.isAborted(err)) {
					errs.push(new Error("Stopping sessions watcher", {cause: err}))
				}

				err = await sseSessions.clear()
				if (err) {
					errs.push(new Error("Clearing sessions", {cause: err}))
				}

				return r.error(new errors.Errors({cause: errs}))
			}

			return r.ok()
		}
	}

	let cleanupStreamable: (() => Promise<r.Result<void, Error>>) | undefined

	if (streamableSessions) {
		let ac = new AbortController()
		let wp = streamableSessions.watch(ac.signal, config.mcp.session.interval)

		cleanupStreamable = async() => {
			if (!ac.signal.aborted) {
				let errs: Error[] = []

				ac.abort("Cleaning up")

				let err = await wp
				if (err && !errors.isAborted(err)) {
					errs.push(new Error("Stopping sessions watcher", {cause: err}))
				}

				err = await streamableSessions.clear()
				if (err) {
					errs.push(new Error("Clearing sessions", {cause: err}))
				}

				return r.error(new errors.Errors({cause: errs}))
			}

			return r.ok()
		}
	}

	let h = e.listen(config.server.port, config.server.host)

	let promise = new Promise<r.Result<void, Error>>((res) => {
		let onError = (err: Error): void => {
			close(new Error("Starting HTTP server", {cause: err}))
		}

		let onListening = (): void => {
			let o: Record<string, unknown> = {
				host: config.server.host,
				port: config.server.port,
			}
			logger.info("Server started", o)
			close()
		}

		let close = (err?: Error): void => {
			h.removeListener("error", onError)
			h.removeListener("listening", onListening)

			if (err) {
				res(r.error(err))
			} else {
				res(r.ok())
			}
		}

		h.once("error", onError)
		h.once("listening", onListening)
	})

	let cleanup = async(): Promise<r.Result<void, Error>> => {
		let errs: Error[] = []

		if (cleanupSse) {
			let c = await cleanupSse()
			if (c.err) {
				errs.push(new Error("Cleaning up SSE", {cause: c.err}))
			}
		}

		if (cleanupStreamable) {
			let c = await cleanupStreamable()
			if (c.err) {
				errs.push(new Error("Cleaning up Streamable HTTP", {cause: c.err}))
			}
		}

		if (h.listening) {
			let p = await new Promise<r.Result<void, Error>>((res) => {
				h.close((err) => {
					if (err) {
						res(r.error(new Error("Closing HTTP server", {cause: err})))
					} else {
						res(r.ok())
					}
				})
			})
			if (p.err) {
				errs.push(p.err)
			}
		}

		if (errs.length !== 0) {
			return r.error(new errors.Errors({cause: errs}))
		}

		return r.ok()
	}

	let s: Start = {
		promise,
		cleanup,
	}

	return r.ok(s)
}

void main()
