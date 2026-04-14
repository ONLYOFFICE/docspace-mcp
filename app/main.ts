#!/usr/bin/env node

import events from "node:events"
import * as stdio from "@modelcontextprotocol/sdk/server/stdio.js"
import type * as types from "@modelcontextprotocol/sdk/types.js"
import express from "express"
import type * as z from "zod"
import * as apiCore from "../lib/api/core.ts"
import * as apiExtra from "../lib/api/extra.ts"
import * as auth from "../lib/auth.ts"
import * as config from "../lib/config.ts"
import * as mcp from "../lib/mcp.ts"
import * as meta from "../lib/meta.ts"
import * as oauth from "../lib/oauth.ts"
import * as utilAbort from "../lib/util/abort.ts"
import * as errors from "../lib/util/errors.ts"
import * as utilExpress from "../lib/util/express.ts"
import * as utilFetch from "../lib/util/fetch.ts"
import * as utilForwarded from "../lib/util/forwarded.ts"
import * as utilLogger from "../lib/util/logger.ts"
import * as utilMcp from "../lib/util/mcp.ts"
import * as r from "../lib/util/result.ts"
import * as utilTrace from "../lib/util/trace.ts"

type Start = {
	promise: Promise<r.Result<void, Error>>
	cleanup(): Promise<r.Result<void, Error>>
}

async function main(): Promise<void> {
	let l = new utilLogger.Logger(process.stdout, process.stderr)

	try {
		let c = config.EnvSchema.safeParse(process.env)

		if (c.error || c.data.mcp.transport === "stdio") {
			l.mute()
		}

		if (c.error) {
			l.error("Loading config", {err: c.error})
		} else {
			l.info("Loaded config", config.redactEnv(c.data))
		}

		let s: r.Result<Start, Error> | undefined

		if (c.error || c.data.mcp.transport === "stdio") {
			s = startStdio(c)
		} else {
			s = startHttp(c.data, l)
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

function startStdio(env: z.ZodSafeParseResult<config.Env>): r.Result<Start, Error> {
	let create = (): r.Result<utilMcp.Protocol, Error> => {
		let ca: (() => void)[] = []

		let mp = new utilMcp.Protocol()

		let mi: types.Implementation = {
			name: meta.name,
			version: meta.version,
		}

		let ms = new utilMcp.Server(mp, mi)

		let mu = mp.registerRouter(ms.router())
		if (mu.err) {
			return r.error(new Error("Registering server router", {cause: mu.err}))
		}

		if (env.error) {
			let ms = new mcp.ErroredServer(env.error)

			mu = mp.registerRouter(ms.router())
			if (mu.err) {
				return r.error(new Error("Registering errored server router", {cause: mu.err}))
			}
		} else {
			let ml = new utilMcp.Logger(mp)

			mu = mp.registerRouter(ml.router())
			if (mu.err) {
				return r.error(new Error("Registering logger router", {cause: mu.err}))
			}

			let me = new utilMcp.Elicitation(mp)

			let mr = new utilMcp.Progress(mp)

			let fetch = globalThis.fetch

			fetch = utilFetch.withLogger(ml, globalThis.fetch)
			fetch = utilAbort.wrapFetch(fetch)

			let cc: apiCore.ClientConfig = {
				userAgent: env.data.api.userAgent,
				baseUrl: env.data.api.shared.baseUrl,
				fetch,
			}

			let c = new apiCore.Client(cc)

			if (env.data.api.shared.authorization) {
				c = c.withAuth(env.data.api.shared.authorization)
			}

			if (env.data.api.shared.apiKey) {
				c = c.withApiKey(env.data.api.shared.apiKey)
			}

			if (env.data.api.shared.pat) {
				c = c.withAuthToken(env.data.api.shared.pat)
			}

			if (env.data.api.shared.username && env.data.api.shared.password) {
				c = c.withBasicAuth(env.data.api.shared.username, env.data.api.shared.password)
			}

			let fb = new events.EventEmitter<apiExtra.FileOperationBusEventMap>()

			let onError = (): void => {}

			let onClose = (): void => {
				fb.removeListener("error", onError)
			}

			fb.addListener("error", onError)

			ca.push(onClose)

			let fpc: apiExtra.FileOperationPollerConfig = {
				interval: env.data.fileOperation.interval,
				client: c,
				bus: fb,
			}

			let fp = new apiExtra.FileOperationPoller(fpc)

			ca.push(fp.close.bind(fp))

			fp.listen()

			let fcc: apiExtra.FileOperationCallerConfig = {
				timeout: env.data.fileOperation.timeout,
				bus: fb,
			}

			let fc = new apiExtra.FileOperationCaller(fcc)

			let csc: mcp.ServerConfig = {
				dynamic: env.data.mcp.dynamic,
				tools: env.data.mcp.tools,
				elicitation: me,
				progress: mr,
				client: c,
				resolver: new apiExtra.Resolver(c),
				uploader: new apiExtra.Uploader(c),
				fileOperationCaller: fc,
			}

			let cs = new mcp.Server(csc)

			mu = mp.registerRouter(cs.router())
			if (mu.err) {
				return r.error(new Error("Registering server router", {cause: mu.err}))
			}
		}

		mp.onclose = () => {
			for (let cf of ca) {
				cf()
			}
		}

		return r.ok(mp)
	}

	let mp = create()

	let promise: Promise<r.Result<void, Error>> | undefined
	let cleanup: (() => Promise<r.Result<void, Error>>) | undefined

	if (mp.err) {
		promise = Promise.resolve(r.error(new Error("Creating protocol", {cause: mp.err})))

		// eslint-disable-next-line typescript/require-await
		cleanup = async() => {
			return r.ok()
		}
	} else {
		let mt = new stdio.StdioServerTransport()

		promise = new Promise<r.Result<void, Error>>((res) => {
			mp.v.connect(mt).
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

		cleanup = async(): Promise<r.Result<void, Error>> => {
			let c = await r.safeAsync(mt.close.bind(mt))
			if (c.err) {
				return r.error(new Error("Closing transport", {cause: c.err}))
			}
			return r.ok()
		}
	}

	let s: Start = {
		promise,
		cleanup,
	}

	return r.ok(s)
}

function startHttp(env: config.Env, logger: utilLogger.Logger): r.Result<Start, Error> {
	let oauthAuthTokens: oauth.AuthTokens | undefined
	let oauthRouter: express.Router | undefined
	let oauthHandler: express.Handler | undefined

	if (env.api.oauth.baseUrl) {
		let fetch = globalThis.fetch

		fetch = utilFetch.withLogger(logger, fetch)
		fetch = utilAbort.wrapFetch(fetch)
		fetch = utilTrace.wrapFetch(fetch)
		fetch = utilForwarded.wrapFetch(fetch)

		let cc: oauth.ClientConfig = {
			userAgent: env.api.userAgent,
			baseUrl: env.api.oauth.baseUrl,
			fetch,
		}

		let c = r.safeNew(oauth.Client, cc)
		if (c.err) {
			return r.error(new Error("Creating OAuth client", {cause: c.err}))
		}

		let atc: oauth.AuthTokensConfig = {
			algorithm: env.oauth.authToken.algorithm,
			ttl: env.oauth.authToken.ttl,
			secretKey: env.oauth.authToken.secretKey,
		}

		let at = new oauth.AuthTokens(atc)

		let stc: oauth.StateTokensConfig = {
			algorithm: env.oauth.stateToken.algorithm,
			ttl: env.oauth.stateToken.ttl,
			secretKey: env.oauth.stateToken.secretKey,
		}

		let st = new oauth.StateTokens(stc)

		let sc: oauth.ServerConfig = {
			baseUrl: env.server.baseUrl,
			clientId: env.api.oauth.clientId,
			clientSecret: env.api.oauth.clientSecret,
			allowedHostnames: env.server.allowedHostnames,
			corsOrigin: env.server.cors.oauth.origin,
			corsMaxAge: env.server.cors.oauth.maxAge,
			serverMetadataRateLimitCapacity: env.server.rateLimits.oauth.serverMetadata.capacity,
			serverMetadataRateLimitWindow: env.server.rateLimits.oauth.serverMetadata.window,
			resourceMetadataRateLimitCapacity: env.server.rateLimits.oauth.resourceMetadata.capacity,
			resourceMetadataRateLimitWindow: env.server.rateLimits.oauth.resourceMetadata.window,
			authorizeRateLimitCapacity: env.server.rateLimits.oauth.authorize.capacity,
			authorizeRateLimitWindow: env.server.rateLimits.oauth.authorize.window,
			callbackRateLimitCapacity: env.server.rateLimits.oauth.callback.capacity,
			callbackRateLimitWindow: env.server.rateLimits.oauth.callback.window,
			introspectRateLimitCapacity: env.server.rateLimits.oauth.introspect.capacity,
			introspectRateLimitWindow: env.server.rateLimits.oauth.introspect.window,
			registerRateLimitCapacity: env.server.rateLimits.oauth.register.capacity,
			registerRateLimitWindow: env.server.rateLimits.oauth.register.window,
			revokeRateLimitCapacity: env.server.rateLimits.oauth.revoke.capacity,
			revokeRateLimitWindow: env.server.rateLimits.oauth.revoke.window,
			tokenRateLimitCapacity: env.server.rateLimits.oauth.token.capacity,
			tokenRateLimitWindow: env.server.rateLimits.oauth.token.window,
			client: c.v,
			authTokens: at,
			stateTokens: st,
		}

		let s = r.safeNew(oauth.Server, sc)
		if (s.err) {
			return r.error(new Error("Creating OAuth server", {cause: s.err}))
		}

		let hc: oauth.HandlerConfig = {
			baseUrl: env.server.baseUrl,
			client: c.v,
			authTokens: at,
		}

		let h = oauth.handler(hc)
		if (h.err) {
			return r.error(new Error("Creating OAuth handler", {cause: h.err}))
		}

		oauthAuthTokens = at
		oauthRouter = s.v.router()
		oauthHandler = h.v
	}

	let credentialParserRequestHeaders: string[] | undefined
	let credentialParser: auth.AuthManagerCredentialParser | undefined

	if (env.internal) {
		let icp = new auth.InternalCredentialParser()

		credentialParserRequestHeaders = icp.requestHeaders
		credentialParser = icp
	} else {
		let cpc: auth.CredentialParserConfig = {
			queryEnabled: env.request.queryEnabled,
			headerPrefix: env.request.headerPrefix,
		}

		let cp = new auth.CredentialParser(cpc)

		credentialParserRequestHeaders = cp.requestHeaders
		credentialParser = cp
	}

	let amc: auth.AuthManagerConfig = {
		defaultBaseUrl: env.api.shared.baseUrl,
		defaultAuth: env.api.shared.authorization,
		defaultApiKey: env.api.shared.apiKey,
		defaultPat: env.api.shared.pat,
		defaultUsername: env.api.shared.username,
		defaultPassword: env.api.shared.password,
		oauthEnabled: false,
		headerEnabled: env.request.headerEnabled,
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

	if (env.api.oauth.baseUrl) {
		amc.oauthEnabled = true
	}

	if (oauthAuthTokens) {
		amc.oauthAuthTokens = oauthAuthTokens
	}

	if (oauthHandler) {
		amc.oauthHandlerRequestHeaders = oauth.handlerRequestHeaders
		amc.oauthHandlerResponseHeaders = oauth.handlerResponseHeaders
		amc.oauthHandler = oauthHandler
	}

	let am = new auth.AuthManager(amc)

	let authHandler = am.handler()

	let spc: config.SettingsParserConfig = {
		defaultDynamic: env.mcp.dynamic,
		defaultToolsets: env.mcp.toolsets,
		defaultTools: env.mcp.tools,
		queryEnabled: env.request.queryEnabled,
		headerPrefix: env.request.headerPrefix,
	}

	let sp = new config.SettingsParser(spc)

	let create = (req: express.Request): r.Result<utilMcp.Protocol, Error> => {
		let s = sp.parse(req)
		if (s.err) {
			return r.error(new Error("Parsing settings", {cause: s.err}))
		}

		let ca: (() => void)[] = []

		let mp = new utilMcp.Protocol()

		let mi: types.Implementation = {
			name: meta.name,
			version: meta.version,
		}

		let ms = new utilMcp.Server(mp, mi)

		let mu = mp.registerRouter(ms.router())
		if (mu.err) {
			return r.error(new Error("Registering server router", {cause: mu.err}))
		}

		let ml = new utilMcp.Logger(mp)

		mu = mp.registerRouter(ml.router())
		if (mu.err) {
			return r.error(new Error("Registering logger router", {cause: mu.err}))
		}

		let me = new utilMcp.Elicitation(mp)

		let mr = new utilMcp.Progress(mp)

		let fetch = globalThis.fetch

		fetch = utilFetch.withLogger(logger, fetch)
		fetch = utilFetch.withLogger(ml, fetch)
		fetch = utilAbort.wrapFetch(fetch)
		fetch = utilTrace.wrapFetch(fetch)
		fetch = utilForwarded.wrapFetch(fetch)

		let cc: apiCore.ClientConfig = {
			userAgent: env.api.userAgent,
			baseUrl: "",
			fetch,
		}

		if (req[oauth.oauthKey]) {
			cc.baseUrl = req[oauth.oauthKey].aud
		}

		if (req[auth.authKey]) {
			cc.baseUrl = req[auth.authKey].baseUrl
		}

		let c = new apiCore.Client(cc)

		if (req[oauth.oauthKey]) {
			c = c.withBearerAuth(req[oauth.oauthKey].token)
		}

		if (req[auth.authKey] && req[auth.authKey].auth) {
			c = c.withAuth(req[auth.authKey].auth)
		}

		if (req[auth.authKey] && req[auth.authKey].apiKey) {
			c = c.withApiKey(req[auth.authKey].apiKey)
		}

		if (req[auth.authKey] && req[auth.authKey].pat) {
			c = c.withAuthToken(req[auth.authKey].pat)
		}

		if (req[auth.authKey] && req[auth.authKey].username && req[auth.authKey].password) {
			c = c.withBasicAuth(req[auth.authKey].username, req[auth.authKey].password)
		}

		let fb = new events.EventEmitter<apiExtra.FileOperationBusEventMap>()

		let onError = (): void => {}

		let onClose = (): void => {
			fb.removeListener("error", onError)
		}

		fb.addListener("error", onError)

		ca.push(onClose)

		let fpc: apiExtra.FileOperationPollerConfig = {
			interval: env.fileOperation.interval,
			client: c,
			bus: fb,
		}

		let fp = new apiExtra.FileOperationPoller(fpc)

		ca.push(fp.close.bind(fp))

		fp.listen()

		let fcc: apiExtra.FileOperationCallerConfig = {
			timeout: env.fileOperation.timeout,
			bus: fb,
		}

		let fc = new apiExtra.FileOperationCaller(fcc)

		let csc: mcp.ServerConfig = {
			dynamic: s.v.dynamic,
			tools: s.v.tools,
			elicitation: me,
			progress: mr,
			client: c,
			resolver: new apiExtra.Resolver(c),
			uploader: new apiExtra.Uploader(c),
			fileOperationCaller: fc,
		}

		let cs = new mcp.Server(csc)

		mu = mp.registerRouter(cs.router())
		if (mu.err) {
			return r.error(new Error("Registering server router", {cause: mu.err}))
		}

		mp.onclose = () => {
			for (let cf of ca) {
				cf()
			}
		}

		return r.ok(mp)
	}

	let sseSessions: mcp.Sessions | undefined
	let sseRouter: express.Router | undefined

	if (env.mcp.transport === "sse" || env.mcp.transport === "http") {
		let sc: mcp.SessionsConfig = {
			ttl: env.mcp.session.ttl,
		}

		let s = new mcp.Sessions(sc)

		let stc: mcp.SseTransportsConfig = {
			logger,
			sessions: s,
		}

		let st = new mcp.SseTransports(stc)

		let ssc: mcp.SseServerConfig = {
			allowedHostnames: env.server.allowedHostnames,
			corsOrigin: env.server.cors.mcp.origin,
			corsMaxAge: env.server.cors.mcp.maxAge,
			corsAllowedHeaders: [
				...am.requestHeaders,
				...sp.requestHeaders,
			],
			corsExposedHeaders: [
				...am.responseHeaders,
			],
			rateLimitCapacity: env.server.rateLimits.mcp.capacity,
			rateLimitWindow: env.server.rateLimits.mcp.window,
			handlers: [
				authHandler,
			],
			protocols: {
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

	if (env.mcp.transport === "streamable-http" || env.mcp.transport === "http") {
		let sc: mcp.SessionsConfig = {
			ttl: env.mcp.session.ttl,
		}

		let s = new mcp.Sessions(sc)

		let stc: mcp.StreamableTransportsConfig = {
			logger,
			sessions: s,
		}

		let st = new mcp.StreamableTransports(stc)

		let ssc: mcp.StreamableServerConfig = {
			allowedHostnames: env.server.allowedHostnames,
			corsOrigin: env.server.cors.mcp.origin,
			corsMaxAge: env.server.cors.mcp.maxAge,
			corsAllowedHeaders: [
				...am.requestHeaders,
				...sp.requestHeaders,
			],
			corsExposedHeaders: [
				...am.responseHeaders,
			],
			rateLimitCapacity: env.server.rateLimits.mcp.capacity,
			rateLimitWindow: env.server.rateLimits.mcp.window,
			handlers: [
				authHandler,
			],
			protocols: {
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

	if (env.proxy.hops) {
		e.set("trust proxy", env.proxy.hops)
	}

	e.use(utilExpress.logger(logger))
	e.use(utilAbort.expressHandler())
	e.use(utilTrace.expressHandler())
	e.use(utilForwarded.expressHandler())
	e.use(utilMcp.expressHandler())

	if (oauthRouter) {
		e.use(oauthRouter)
	}

	if (sseRouter) {
		e.use(sseRouter)
	}

	if (streamableRouter) {
		e.use(streamableRouter)
	}

	e.use("/health", (_, res) => {
		res.status(200)
		res.end()
	})

	e.use((_, res) => {
		let err = new errors.JsonError("Not Found")
		res.status(404)
		res.json(err.toObject())
	})

	let cleanupSse: (() => Promise<r.Result<void, Error>>) | undefined

	if (sseSessions) {
		let ac = new AbortController()
		let wp = sseSessions.watch(ac.signal, env.mcp.session.interval)

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

				return r.error(new AggregateError(errs, "Cleaning up sessions"))
			}

			return r.ok()
		}
	}

	let cleanupStreamable: (() => Promise<r.Result<void, Error>>) | undefined

	if (streamableSessions) {
		let ac = new AbortController()
		let wp = streamableSessions.watch(ac.signal, env.mcp.session.interval)

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

				return r.error(new AggregateError(errs, "Cleaning up sessions"))
			}

			return r.ok()
		}
	}

	let h = e.listen(env.server.port, env.server.host)

	let promise = new Promise<r.Result<void, Error>>((res) => {
		let onError = (err: Error): void => {
			close(new Error("Starting HTTP server", {cause: err}))
		}

		let onListening = (): void => {
			let o: Record<string, unknown> = {
				host: env.server.host,
				port: env.server.port,
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
			return r.error(new AggregateError(errs, "Calling cleanups"))
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
