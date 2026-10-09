/**
 * @module
 * @mergeModuleWith mcp
 */

import type * as streamableHttp from "@modelcontextprotocol/sdk/server/streamableHttp.js"
import type * as transport from "@modelcontextprotocol/sdk/shared/transport.js"
import * as types from "@modelcontextprotocol/sdk/types.js"
import express from "express"
import * as errors from "../util/errors.ts"
import * as utilExpress from "../util/express.ts"
import * as result from "../util/result.ts"

export type StreamableServerConfig = {
  allowedHostnames: string[]
  corsOrigin: string[]
  corsMaxAge: number
  corsAllowedHeaders: string[]
  corsExposedHeaders: string[]
  rateLimitCapacity: number
  rateLimitWindow: number
  handlers: express.Handler[]
  protocols: StreamableServerProtocols
  transports: StreamableServerTransports
}

export type StreamableServerProtocol = {
  connect(transport: transport.Transport): Promise<void>
}

export type StreamableServerProtocols = {
  create(req: express.Request): result.Result<StreamableServerProtocol, Error>
}

export type StreamableServerTransports = {
  create(): streamableHttp.StreamableHTTPServerTransport
  retrieve(id: string): result.Result<streamableHttp.StreamableHTTPServerTransport, Error>
}

export class StreamableServer {
  private allowedHostnames: string[]
  private corsOrigin: string[]
  private corsMaxAge: number
  private corsAllowedHeaders: string[]
  private corsExposedHeaders: string[]
  private rateLimitCapacity: number
  private rateLimitWindow: number
  private handlers: express.Handler[]
  private protocols: StreamableServerProtocols
  private transports: StreamableServerTransports

  constructor(config: StreamableServerConfig) {
    this.allowedHostnames = config.allowedHostnames
    this.corsOrigin = config.corsOrigin
    this.corsMaxAge = config.corsMaxAge
    this.corsAllowedHeaders = config.corsAllowedHeaders
    this.corsExposedHeaders = config.corsExposedHeaders
    this.rateLimitCapacity = config.rateLimitCapacity
    this.rateLimitWindow = config.rateLimitWindow
    this.handlers = config.handlers
    this.protocols = config.protocols
    this.transports = config.transports
  }

  router(): express.Router {
    // todo: add recovery middleware
    // todo: add allowedMethods middleware
    // todo: add supportedMediaTypes middleware

    const allowedHostnames = (r: express.Router): void => {
      if (this.allowedHostnames.length !== 0) {
        r.use(utilExpress.allowedHostnames(this.allowedHostnames, (_, res, err) => {
          // todo: use proper type
          const er: object = {
            jsonrpc: "2.0",
            error: {
              code: -32000,
              message: errors.format(err),
            },
            id: null,
          }

          res.json(er)
        }))
      }
    }

    const cors = (r: express.Router): void => {
      if (this.corsOrigin.length !== 0) {
        const co: utilExpress.CorsOptions = {
          origin: this.corsOrigin,
          maxAge: this.corsMaxAge,
          methods: ["GET", "POST", "DELETE"],
          allowedHeaders: [
            ...this.corsAllowedHeaders,
            "Content-Type",
            "Mcp-Session-Id",
          ],
          exposedHeaders: [
            ...this.corsExposedHeaders,
            "Mcp-Session-Id",
          ],
        }

        if (this.rateLimitCapacity && this.rateLimitWindow) {
          co.exposedHeaders.push(...utilExpress.rateLimitHeaders)
        }

        r.use(utilExpress.cors(co))
      }
    }

    const guard = (r: express.Router): void => {
      if (this.rateLimitCapacity && this.rateLimitWindow) {
        const er = new errors.
          JsonrpcError(
            -32000,
            "Too many requests, please try again later",
          ).
          toObject()

        const ro: utilExpress.RateLimitOptions = {
          capacity: this.rateLimitCapacity,
          window: this.rateLimitWindow,
        }

        r.use(utilExpress.rateLimit(ro, (_, res) => {
          res.json(er)
        }))
      }
    }

    const r = express.Router()

    r.use("/mcp", (() => {
      const r = express.Router()

      r.use(express.json())

      allowedHostnames(r)
      cors(r)

      r.use(...this.handlers)

      guard(r)

      r.post("/", this.handlePost.bind(this))
      r.get("/", this.handleGetDelete.bind(this))
      r.delete("/", this.handleGetDelete.bind(this))

      return r
    })())

    return r
  }

  private async handlePost(req: express.Request, res: express.Response): Promise<void> {
    try {
      const id = req.headers["mcp-session-id"]
      let t: streamableHttp.StreamableHTTPServerTransport | undefined

      if (id === undefined || id === "") {
        if (types.isInitializeRequest(req.body)) {
          const s = this.protocols.create(req)
          if (s.err) {
            // It is most likely 400, rather than 500.
            const err = new errors.JsonrpcError(
              -32000,
              "Creating protocol",
              {cause: s.err},
            )
            res.status(400)
            res.json(err.toObject())
            return
          }

          t = this.transports.create()

          const c = await result.safeAsync(s.v.connect.bind(s.v), t)
          if (c.err) {
            const err = new errors.JsonrpcError(
              -32603,
              "Attaching server",
              {cause: c.err},
            )
            res.status(500)
            res.json(err.toObject())
            return
          }
        } else {
          // https://github.com/modelcontextprotocol/typescript-sdk/blob/1.15.1/src/server/streamableHttp.ts#L587
          const err = new errors.JsonrpcError(
            -32000,
            "Bad Request: Mcp-Session-Id header is required",
          )
          res.status(400)
          res.json(err.toObject())
          return
        }
      } else if (Array.isArray(id)) {
        // https://github.com/modelcontextprotocol/typescript-sdk/blob/1.15.1/src/server/streamableHttp.ts#L597
        const err = new errors.JsonrpcError(
          -32000,
          "Bad Request: Mcp-Session-Id header must be a single value",
        )
        res.status(400)
        res.json(err.toObject())
        return
      } else {
        const r = this.transports.retrieve(id)
        if (r.err) {
          const err = new errors.JsonrpcError(
            -32001,
            "Retrieving transport",
            {cause: r.err},
          )
          res.status(404)
          res.json(err.toObject())
          return
        }

        t = r.v
      }

      const h = await result.safeAsync(t.handleRequest.bind(t), req, res, req.body)
      if (h.err) {
        // The handleRequest will most likely populate the response itself;
        // however, if it does not, we will do it ourselves.
        if (res.headersSent) {
          if (!res.writableEnded) {
            res.end()
          }
        } else {
          const err = new errors.JsonrpcError(
            -32603,
            "Handling request",
            {cause: h.err},
          )
          res.status(500)
          res.json(err.toObject())
        }
        return
      }
    } catch (err_) {
      if (res.headersSent) {
        if (!res.writableEnded) {
          res.end()
        }
      } else {
        const err = new errors.JsonrpcError(
          -32603,
          "Internal Server Error",
          {cause: err_},
        )
        res.status(500)
        res.json(err.toObject())
      }
    }
  }

  private async handleGetDelete(req: express.Request, res: express.Response): Promise<void> {
    try {
      const id = req.headers["mcp-session-id"]

      if (id === undefined || id === "") {
        // https://github.com/modelcontextprotocol/typescript-sdk/blob/1.15.1/src/server/streamableHttp.ts#L587
        const err = new errors.JsonrpcError(
          -32000,
          "Bad Request: Mcp-Session-Id header is required",
        )
        res.status(400)
        res.json(err.toObject())
        return
      }

      if (Array.isArray(id)) {
        // https://github.com/modelcontextprotocol/typescript-sdk/blob/1.15.1/src/server/streamableHttp.ts#L597
        const err = new errors.JsonrpcError(
          -32000,
          "Bad Request: Mcp-Session-Id header must be a single value",
        )
        res.status(400)
        res.json(err.toObject())
        return
      }

      const r = this.transports.retrieve(id)
      if (r.err) {
        const err = new errors.JsonrpcError(
          -32001,
          "Retrieving transport",
          {cause: r.err},
        )
        res.status(404)
        res.json(err.toObject())
        return
      }

      const h = await result.safeAsync(r.v.handleRequest.bind(r.v), req, res)
      if (h.err) {
        // The handleRequest will most likely populate the response itself;
        // however, if it does not, we will do it ourselves.
        if (res.headersSent) {
          if (!res.writableEnded) {
            res.end()
          }
        } else {
          const err = new errors.JsonrpcError(
            -32603,
            "Handling request",
            {cause: h.err},
          )
          res.status(500)
          res.json(err.toObject())
        }
        return
      }
    } catch (err_) {
      if (res.headersSent) {
        if (!res.writableEnded) {
          res.end()
        }
      } else {
        const err = new errors.JsonrpcError(
          -32603,
          "Internal Server Error",
          {cause: err_},
        )
        res.status(500)
        res.json(err.toObject())
      }
    }
  }
}
