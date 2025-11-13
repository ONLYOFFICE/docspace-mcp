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

import type http from "node:http"
import type * as server from "@modelcontextprotocol/sdk/server/index.js"
import express from "express"
import * as api from "../lib/api.ts"
import * as mcp from "../lib/mcp.ts"
import * as context from "../lib/util/context.ts"
import * as errors from "../lib/util/errors.ts"
import * as utilExpress from "../lib/util/express.ts"
import * as utilFetch from "../lib/util/fetch.ts"
import * as logger from "../lib/util/logger.ts"
import * as utilMcp from "../lib/util/mcp.ts"
import * as result from "../lib/util/result.ts"
import * as config from "./config.ts"
import * as shared from "./shared.ts"

type CreateServer = (req: express.Request) => result.Result<server.Server, Error>

interface Components {
	sse: Mcp | undefined
	streamable: Mcp | undefined
}

interface Mcp {
	sessions: mcp.Sessions
	server: express.Router
}

interface App {
	sse: Watchable | undefined
	streamable: Watchable | undefined
	server: http.Server
}

interface Watchable {
	controller: AbortController
	promise: shared.P
}

export function start(
	g: config.global.Config,
	l: logger.VanillaLogger,
): [shared.P, shared.Cleanup] {
	let create = createCreateServer(g, l)

	let c = createComponents(g, l, create)
	if (c.err) {
		// eslint-disable-next-line typescript/require-await
		return [Promise.resolve(c.err), async() => undefined]
	}

	let e = createExpress(g, l, c.v)

	let a = createApp(g, c.v, e)

	let cleanup = createCleanup(c.v, a)

	let p = createPromise(g, l, a.server)

	return [p, cleanup]
}

function createCreateServer(
	g: config.global.Config,
	l: logger.VanillaLogger,
): CreateServer {
	if (g.internal) {
		return createInternalCreateServer(g, l)
	}
	return createCreateServerWithAuth(g, l)
}

function createInternalCreateServer(
	g: config.global.Config,
	l: logger.VanillaLogger,
): CreateServer {
	return (req: express.Request): result.Result<server.Server, Error> => {
		let a = req.headers.authorization
		if (!a) {
			return result.error(new Error("Authorization header is required"))
		}

		let r = req.headers.referer
		if (!r) {
			return result.error(new Error("Referer header is required"))
		}

		let b = result.safeNew(URL, r)
		if (b.err) {
			return result.error(new Error("Creating base URL", {cause: b.err}))
		}

		if (!b.v.pathname.endsWith("/")) {
			b.v.pathname += "/"
		}

		let s = shared.createServer()

		let e = new logger.ServerLogger(context, s)

		s.registerCapabilities({logging: {}})

		let f = utilFetch.withLogger(context, e, fetch)

		f = utilFetch.withLogger(context, l, f)

		let cc: api.ClientConfig = {
			userAgent: g.api.userAgent,
			baseUrl: b.v.toString(),
			fetch: f,
		}

		let c = new api.Client(cc)

		c = c.withAuthToken(a)

		let sc: mcp.ConfiguredServerConfig = {
			client: c,
			resolver: new api.Resolver(c),
			uploader: new api.Uploader(c),
			dynamic: g.mcp.dynamic,
			tools: g.mcp.tools,
		}

		let defs = mcp.configuredServer(sc)

		utilMcp.register(s, defs)

		return result.ok(s)
	}
}

function createCreateServerWithAuth(
	g: config.global.Config,
	l: logger.VanillaLogger,
): CreateServer {
	return (req) => {
		let a = config.request.parseApiShared(g, req)
		if (a.err) {
			return result.error(new Error("Parsing API shared config", {cause: a.err}))
		}

		let m = config.request.parseMcp(g, req)
		if (m.err) {
			return result.error(new Error("Parsing MCP config", {cause: m.err}))
		}

		let s = shared.createServer()

		let e = new logger.ServerLogger(context, s)

		s.registerCapabilities({logging: {}})

		let f = utilFetch.withLogger(context, e, fetch)

		f = utilFetch.withLogger(context, l, f)

		let cc: api.ClientConfig = {
			userAgent: g.api.userAgent,
			baseUrl: a.v.baseUrl,
			fetch: f,
		}

		let c = new api.Client(cc)

		if (a.v.authorization) {
			c = c.withAuth(a.v.authorization)
		}

		if (a.v.apiKey) {
			c = c.withApiKey(a.v.apiKey)
		}

		if (a.v.pat) {
			c = c.withAuthToken(a.v.pat)
		}

		if (a.v.username && a.v.password) {
			c = c.withBasicAuth(a.v.username, a.v.password)
		}

		let sc: mcp.ConfiguredServerConfig = {
			client: c,
			resolver: new api.Resolver(c),
			uploader: new api.Uploader(c),
			dynamic: m.v.dynamic,
			tools: m.v.tools,
		}

		let defs = mcp.configuredServer(sc)

		utilMcp.register(s, defs)

		return result.ok(s)
	}
}

function createComponents(
	g: config.global.Config,
	l: logger.VanillaLogger,
	create: CreateServer,
): result.Result<Components, Error> {
	let c: Components = {
		sse: undefined,
		streamable: undefined,
	}

	switch (g.mcp.transport) {
	case "sse":
		c.sse = createSse(g, l, create)
		break
	case "streamable-http":
		c.streamable = createStreamable(g, l, create)
		break
	case "http":
		c.sse = createSse(g, l, create)
		c.streamable = createStreamable(g, l, create)
		break
	// no default
	}

	return result.ok(c)
}

function createSse(
	g: config.global.Config,
	l: logger.VanillaLogger,
	create: CreateServer,
): Mcp {
	let sc: mcp.SessionsConfig = {
		ttl: g.mcp.session.ttl,
	}

	let s = new mcp.Sessions(sc)

	let tc: mcp.SseTransportsConfig = {
		logger: l,
		sessions: s,
	}

	let t = new mcp.SseTransports(tc)

	let rc: mcp.SseServerConfig = {
		corsOrigin: g.server.cors.mcp.origin,
		corsMaxAge: g.server.cors.mcp.maxAge,
		corsAllowedHeaders: [],
		corsExposedHeaders: [],
		rateLimitCapacity: g.server.rateLimits.mcp.capacity,
		rateLimitWindow: g.server.rateLimits.mcp.window,
		handlers: [],
		servers: {
			create,
		},
		transports: t,
	}

	let r = new mcp.SseServer(rc)

	let m: Mcp = {
		sessions: s,
		server: r.router(),
	}

	return m
}

function createStreamable(
	g: config.global.Config,
	l: logger.VanillaLogger,
	create: CreateServer,
): Mcp {
	let sc: mcp.SessionsConfig = {
		ttl: g.mcp.session.ttl,
	}

	let s = new mcp.Sessions(sc)

	let tc: mcp.StreamableTransportsConfig = {
		logger: l,
		sessions: s,
	}

	let t = new mcp.StreamableTransports(tc)

	let rc: mcp.StreamableServerConfig = {
		corsOrigin: g.server.cors.mcp.origin,
		corsMaxAge: g.server.cors.mcp.maxAge,
		corsAllowedHeaders: [],
		corsExposedHeaders: [],
		rateLimitCapacity: g.server.rateLimits.mcp.capacity,
		rateLimitWindow: g.server.rateLimits.mcp.window,
		handlers: [],
		servers: {
			create,
		},
		transports: t,
	}

	let r = new mcp.StreamableServer(rc)

	let m: Mcp = {
		sessions: s,
		server: r.router(),
	}

	return m
}

function createExpress(
	g: config.global.Config,
	l: logger.VanillaLogger,
	c: Components,
): express.Express {
	let e = express()

	e.disable("x-powered-by")
	e.disable("etag")
	e.set("json spaces", 2)

	if (g.server.proxy.hops) {
		e.set("trust proxy", g.server.proxy.hops)
	}

	e.use(utilExpress.context(context))
	e.use(utilExpress.logger(context, l))

	if (c.sse) {
		e.use(c.sse.server)
	}

	if (c.streamable) {
		e.use(c.streamable.server)
	}

	e.use(notFound())

	return e
}

function createApp(g: config.global.Config, c: Components, e: express.Express): App {
	let sse: Watchable | undefined

	if (c.sse) {
		let a = new AbortController()
		let w = c.sse.sessions.watch(a.signal, g.mcp.session.interval)
		sse = {
			controller: a,
			promise: w,
		}
	}

	let streamable: Watchable | undefined

	if (c.streamable) {
		let a = new AbortController()
		let w = c.streamable.sessions.watch(a.signal, g.mcp.session.interval)
		streamable = {
			controller: a,
			promise: w,
		}
	}

	let h = e.listen(g.server.port, g.server.host)

	let a: App = {
		sse,
		streamable,
		server: h,
	}

	return a
}

function createCleanup(c: Components, a: App): shared.Cleanup {
	return async() => {
		let errs: Error[] = []

		if (c.sse && a.sse && !a.sse.controller.signal.aborted) {
			a.sse.controller.abort("Cleaning up")

			let err = await a.sse.promise
			if (err && !errors.isAborted(err)) {
				errs.push(new Error("Stopping sse sessions watcher", {cause: err}))
			}

			err = await c.sse.sessions.clear()
			if (err) {
				errs.push(new Error("Clearing sse sessions", {cause: err}))
			}
		}

		if (c.streamable && a.streamable && !a.streamable.controller.signal.aborted) {
			a.streamable.controller.abort("Cleaning up")

			let err = await a.streamable.promise
			if (err && !errors.isAborted(err)) {
				errs.push(new Error("Stopping streamable sessions watcher", {cause: err}))
			}

			err = await c.streamable.sessions.clear()
			if (err) {
				errs.push(new Error("Clearing streamable sessions", {cause: err}))
			}
		}

		if (a.server.listening) {
			let err = await new Promise<Error | undefined>((res) => {
				a.server.close((err) => {
					if (err) {
						res(new Error("Closing HTTP server", {cause: err}))
					} else {
						res(undefined)
					}
				})
			})

			if (err) {
				errs.push(err)
			}
		}

		if (errs.length !== 0) {
			return new errors.Errors({cause: errs})
		}
	}
}

async function createPromise(
	g: config.global.Config,
	l: logger.VanillaLogger,
	h: http.Server,
): shared.P {
	return await new Promise((res) => {
		h.once("error", onError)
		h.once("listening", onListening)

		function onError(err: Error): void {
			close(new Error("Starting HTTP server", {cause: err}))
		}

		function onListening(): void {
			let o: Record<string, unknown> = {
				host: g.server.host,
				port: g.server.port,
			}
			l.info("Server started", o)
			close()
		}

		function close(err?: Error): void {
			h.removeListener("error", onError)
			h.removeListener("listening", onListening)
			res(err)
		}
	})
}

function notFound(): express.Handler {
	return (_, res) => {
		let err = new errors.JsonError("Not Found")
		res.status(404)
		res.json(err.toObject())
	}
}
