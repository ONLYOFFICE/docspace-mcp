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
  const l = new utilLogger.Logger(process.stdout, process.stderr)

  try {
    const c = config.EnvSchema.safeParse(process.env)

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

    for (const e of ["SIGTERM", "SIGINT"]) {
      process.on(e, () => {
        void (async() => {
          l.info(`Received ${e}, shutting down`)

          const c = await s.v.cleanup()
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

    const p = await s.v.promise
    if (p.err) {
      l.error("Server failed to start", {err: p.err})

      const c = await s.v.cleanup()
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
  const create = (): r.Result<utilMcp.Protocol, Error> => {
    const ca: (() => void)[] = []

    const mp = new utilMcp.Protocol()

    const mi: types.Implementation = {
      name: meta.name,
      version: meta.version,
    }

    const ms = new utilMcp.Server(mp, mi)

    let mu = mp.registerRouter(ms.router())
    if (mu.err) {
      return r.error(new Error("Registering server router", {cause: mu.err}))
    }

    if (env.error) {
      const ms = new mcp.ErroredServer(env.error)

      mu = mp.registerRouter(ms.router())
      if (mu.err) {
        return r.error(new Error("Registering errored server router", {cause: mu.err}))
      }
    } else {
      const ml = new utilMcp.Logger(mp)

      mu = mp.registerRouter(ml.router())
      if (mu.err) {
        return r.error(new Error("Registering logger router", {cause: mu.err}))
      }

      const me = new utilMcp.Elicitation(mp)

      const mr = new utilMcp.Progress(mp)

      let fetch = globalThis.fetch

      fetch = utilFetch.withLogger(ml, globalThis.fetch)
      fetch = utilAbort.wrapFetch(fetch)

      const cc: apiCore.ClientConfig = {
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

      const fb = new events.EventEmitter<apiExtra.FileOperationBusEventMap>()

      const onError = (): void => {}

      const onClose = (): void => {
        fb.removeListener("error", onError)
      }

      fb.addListener("error", onError)

      ca.push(onClose)

      const fpc: apiExtra.FileOperationPollerConfig = {
        interval: env.data.fileOperation.interval,
        client: c,
        bus: fb,
      }

      const fp = new apiExtra.FileOperationPoller(fpc)

      ca.push(fp.close.bind(fp))

      fp.listen()

      const fcc: apiExtra.FileOperationCallerConfig = {
        timeout: env.data.fileOperation.timeout,
        bus: fb,
      }

      const fc = new apiExtra.FileOperationCaller(fcc)

      const csc: mcp.ServerConfig = {
        dynamic: env.data.mcp.dynamic,
        tools: env.data.mcp.tools,
        elicitation: me,
        progress: mr,
        client: c,
        resolver: new apiExtra.Resolver(c),
        uploader: new apiExtra.Uploader(c),
        fileOperationCaller: fc,
      }

      const cs = new mcp.Server(csc)

      mu = mp.registerRouter(cs.router())
      if (mu.err) {
        return r.error(new Error("Registering server router", {cause: mu.err}))
      }
    }

    mp.onclose = () => {
      for (const cf of ca) {
        cf()
      }
    }

    return r.ok(mp)
  }

  const mp = create()

  let promise: Promise<r.Result<void, Error>> | undefined
  let cleanup: (() => Promise<r.Result<void, Error>>) | undefined

  if (mp.err) {
    promise = Promise.resolve(r.error(new Error("Creating protocol", {cause: mp.err})))

    // eslint-disable-next-line typescript/require-await
    cleanup = async() => {
      return r.ok()
    }
  } else {
    const mt = new stdio.StdioServerTransport()

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
      const c = await r.safeAsync(mt.close.bind(mt))
      if (c.err) {
        return r.error(new Error("Closing transport", {cause: c.err}))
      }
      return r.ok()
    }
  }

  const s: Start = {
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

    const cc: oauth.ClientConfig = {
      userAgent: env.api.userAgent,
      baseUrl: env.api.oauth.baseUrl,
      fetch,
    }

    const c = r.safeNew(oauth.Client, cc)
    if (c.err) {
      return r.error(new Error("Creating OAuth client", {cause: c.err}))
    }

    const atc: oauth.AuthTokensConfig = {
      algorithm: env.oauth.authToken.algorithm,
      ttl: env.oauth.authToken.ttl,
      secretKey: env.oauth.authToken.secretKey,
    }

    const at = new oauth.AuthTokens(atc)

    const stc: oauth.StateTokensConfig = {
      algorithm: env.oauth.stateToken.algorithm,
      ttl: env.oauth.stateToken.ttl,
      secretKey: env.oauth.stateToken.secretKey,
    }

    const st = new oauth.StateTokens(stc)

    const sc: oauth.ServerConfig = {
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

    const s = r.safeNew(oauth.Server, sc)
    if (s.err) {
      return r.error(new Error("Creating OAuth server", {cause: s.err}))
    }

    const hc: oauth.HandlerConfig = {
      baseUrl: env.server.baseUrl,
      client: c.v,
      authTokens: at,
    }

    const h = oauth.handler(hc)
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
    const icp = new auth.InternalCredentialParser()

    credentialParserRequestHeaders = icp.requestHeaders
    credentialParser = icp
  } else {
    const cpc: auth.CredentialParserConfig = {
      queryEnabled: env.request.queryEnabled,
      headerPrefix: env.request.headerPrefix,
    }

    const cp = new auth.CredentialParser(cpc)

    credentialParserRequestHeaders = cp.requestHeaders
    credentialParser = cp
  }

  const amc: auth.AuthManagerConfig = {
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

  const am = new auth.AuthManager(amc)

  const authHandler = am.handler()

  const spc: config.SettingsParserConfig = {
    defaultDynamic: env.mcp.dynamic,
    defaultToolsets: env.mcp.toolsets,
    defaultTools: env.mcp.tools,
    queryEnabled: env.request.queryEnabled,
    headerPrefix: env.request.headerPrefix,
  }

  const sp = new config.SettingsParser(spc)

  const create = (req: express.Request): r.Result<utilMcp.Protocol, Error> => {
    const s = sp.parse(req)
    if (s.err) {
      return r.error(new Error("Parsing settings", {cause: s.err}))
    }

    const ca: (() => void)[] = []

    const mp = new utilMcp.Protocol()

    const mi: types.Implementation = {
      name: meta.name,
      version: meta.version,
    }

    const ms = new utilMcp.Server(mp, mi)

    let mu = mp.registerRouter(ms.router())
    if (mu.err) {
      return r.error(new Error("Registering server router", {cause: mu.err}))
    }

    const ml = new utilMcp.Logger(mp)

    mu = mp.registerRouter(ml.router())
    if (mu.err) {
      return r.error(new Error("Registering logger router", {cause: mu.err}))
    }

    const me = new utilMcp.Elicitation(mp)

    const mr = new utilMcp.Progress(mp)

    let fetch = globalThis.fetch

    fetch = utilFetch.withLogger(logger, fetch)
    fetch = utilFetch.withLogger(ml, fetch)
    fetch = utilAbort.wrapFetch(fetch)
    fetch = utilTrace.wrapFetch(fetch)
    fetch = utilForwarded.wrapFetch(fetch)

    const cc: apiCore.ClientConfig = {
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

    const fb = new events.EventEmitter<apiExtra.FileOperationBusEventMap>()

    const onError = (): void => {}

    const onClose = (): void => {
      fb.removeListener("error", onError)
    }

    fb.addListener("error", onError)

    ca.push(onClose)

    const fpc: apiExtra.FileOperationPollerConfig = {
      interval: env.fileOperation.interval,
      client: c,
      bus: fb,
    }

    const fp = new apiExtra.FileOperationPoller(fpc)

    ca.push(fp.close.bind(fp))

    fp.listen()

    const fcc: apiExtra.FileOperationCallerConfig = {
      timeout: env.fileOperation.timeout,
      bus: fb,
    }

    const fc = new apiExtra.FileOperationCaller(fcc)

    const csc: mcp.ServerConfig = {
      dynamic: s.v.dynamic,
      tools: s.v.tools,
      elicitation: me,
      progress: mr,
      client: c,
      resolver: new apiExtra.Resolver(c),
      uploader: new apiExtra.Uploader(c),
      fileOperationCaller: fc,
    }

    const cs = new mcp.Server(csc)

    mu = mp.registerRouter(cs.router())
    if (mu.err) {
      return r.error(new Error("Registering server router", {cause: mu.err}))
    }

    mp.onclose = () => {
      for (const cf of ca) {
        cf()
      }
    }

    return r.ok(mp)
  }

  let sseSessions: mcp.Sessions | undefined
  let sseRouter: express.Router | undefined

  if (env.mcp.transport === "sse" || env.mcp.transport === "http") {
    const sc: mcp.SessionsConfig = {
      ttl: env.mcp.session.ttl,
    }

    const s = new mcp.Sessions(sc)

    const stc: mcp.SseTransportsConfig = {
      logger,
      sessions: s,
    }

    const st = new mcp.SseTransports(stc)

    const ssc: mcp.SseServerConfig = {
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

    const ss = new mcp.SseServer(ssc)

    sseSessions = s
    sseRouter = ss.router()
  }

  let streamableSessions: mcp.Sessions | undefined
  let streamableRouter: express.Router | undefined

  if (env.mcp.transport === "streamable-http" || env.mcp.transport === "http") {
    const sc: mcp.SessionsConfig = {
      ttl: env.mcp.session.ttl,
    }

    const s = new mcp.Sessions(sc)

    const stc: mcp.StreamableTransportsConfig = {
      logger,
      sessions: s,
    }

    const st = new mcp.StreamableTransports(stc)

    const ssc: mcp.StreamableServerConfig = {
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

    const ss = new mcp.StreamableServer(ssc)

    streamableSessions = s
    streamableRouter = ss.router()
  }

  const e = express()

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
    const err = new errors.JsonError("Not Found")
    res.status(404)
    res.json(err.toObject())
  })

  let cleanupSse: (() => Promise<r.Result<void, Error>>) | undefined

  if (sseSessions) {
    const ac = new AbortController()
    const wp = sseSessions.watch(ac.signal, env.mcp.session.interval)

    cleanupSse = async() => {
      if (!ac.signal.aborted) {
        const errs: Error[] = []

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
    const ac = new AbortController()
    const wp = streamableSessions.watch(ac.signal, env.mcp.session.interval)

    cleanupStreamable = async() => {
      if (!ac.signal.aborted) {
        const errs: Error[] = []

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

  const h = e.listen(env.server.port, env.server.host)

  const promise = new Promise<r.Result<void, Error>>((res) => {
    const onError = (err: Error): void => {
      close(new Error("Starting HTTP server", {cause: err}))
    }

    const onListening = (): void => {
      const o: Record<string, unknown> = {
        host: env.server.host,
        port: env.server.port,
      }
      logger.info("Server started", o)
      close()
    }

    const close = (err?: Error): void => {
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

  const cleanup = async(): Promise<r.Result<void, Error>> => {
    const errs: Error[] = []

    if (cleanupSse) {
      const c = await cleanupSse()
      if (c.err) {
        errs.push(new Error("Cleaning up SSE", {cause: c.err}))
      }
    }

    if (cleanupStreamable) {
      const c = await cleanupStreamable()
      if (c.err) {
        errs.push(new Error("Cleaning up Streamable HTTP", {cause: c.err}))
      }
    }

    if (h.listening) {
      const p = await new Promise<r.Result<void, Error>>((res) => {
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

  const s: Start = {
    promise,
    cleanup,
  }

  return r.ok(s)
}

void main()
