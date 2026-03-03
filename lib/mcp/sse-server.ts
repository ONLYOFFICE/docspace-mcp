/**
 * @module
 * @mergeModuleWith mcp
 */

import type * as server from "@modelcontextprotocol/sdk/server/index.js"
import type * as sse from "@modelcontextprotocol/sdk/server/sse.js"
import express from "express"
import * as errors from "../util/errors.ts"
import * as utilExpress from "../util/express.ts"
import * as result from "../util/result.ts"

export type SseServerConfig = {
	allowedHostnames: string[]
	corsOrigin: string[]
	corsMaxAge: number
	corsAllowedHeaders: string[]
	corsExposedHeaders: string[]
	rateLimitCapacity: number
	rateLimitWindow: number
	handlers: express.Handler[]
	servers: SseServerServers
	transports: SseServerTransports
}

export type SseServerServers = {
	create(req: express.Request): result.Result<server.Server, Error>
}

export type SseServerTransports = {
	create(endpoint: string, res: express.Response): sse.SSEServerTransport
	retrieve(id: string): result.Result<sse.SSEServerTransport, Error>
}

export class SseServer {
	private allowedHostnames: string[]
	private corsOrigin: string[]
	private corsMaxAge: number
	private corsAllowedHeaders: string[]
	private corsExposedHeaders: string[]
	private rateLimitCapacity: number
	private rateLimitWindow: number
	private handlers: express.Handler[]
	private servers: SseServerServers
	private transports: SseServerTransports

	constructor(config: SseServerConfig) {
		this.allowedHostnames = config.allowedHostnames
		this.corsOrigin = config.corsOrigin
		this.corsMaxAge = config.corsMaxAge
		this.corsAllowedHeaders = config.corsAllowedHeaders
		this.corsExposedHeaders = config.corsExposedHeaders
		this.rateLimitCapacity = config.rateLimitCapacity
		this.rateLimitWindow = config.rateLimitWindow
		this.handlers = config.handlers
		this.servers = config.servers
		this.transports = config.transports
	}

	router(): express.Router {
		// todo: add recovery middleware
		// todo: add allowedMethods middleware
		// todo: add supportedMediaTypes middleware

		let allowedHostnames = (r: express.Router): void => {
			if (this.allowedHostnames.length !== 0) {
				r.use(utilExpress.allowedHostnames(this.allowedHostnames, (_, res, err) => {
					res.end(errors.format(err))
				}))
			}
		}

		let cors = (r: express.Router): void => {
			if (this.corsOrigin.length !== 0) {
				let co: utilExpress.CorsOptions = {
					origin: this.corsOrigin,
					maxAge: this.corsMaxAge,
					methods: ["GET", "POST"],
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

		let guard = (r: express.Router): void => {
			if (this.rateLimitCapacity && this.rateLimitWindow) {
				let er = new errors.
					MessageError("Too many requests, please try again later").
					toString()

				let ro: utilExpress.RateLimitOptions = {
					capacity: this.rateLimitCapacity,
					window: this.rateLimitWindow,
				}

				r.use(utilExpress.rateLimit(ro, (_, res) => {
					res.json(er)
				}))
			}
		}

		let r = express.Router()

		r.use("/sse", (() => {
			let r = express.Router()

			r.use(express.json())

			allowedHostnames(r)
			cors(r)

			r.use(this.handlers)

			guard(r)

			r.get("/", this.handleSse.bind(this))

			return r
		})())

		r.use("/messages", (() => {
			let r = express.Router()

			r.use(express.json())

			allowedHostnames(r)
			cors(r)

			r.use(this.handlers)

			guard(r)

			r.post("/", this.handleMessages.bind(this))

			return r
		})())

		return r
	}

	private async handleSse(req: express.Request, res: express.Response): Promise<void> {
		try {
			let s = this.servers.create(req)
			if (s.err) {
				// It is most likely 400, rather than 500.
				let err = new errors.MessageError("Creating server", {cause: s.err})
				res.writeHead(400)
				res.end(err.toString())
				return
			}

			let t = this.transports.create("/messages", res)

			let c = await result.safeAsync(s.v.connect.bind(s.v), t)
			if (c.err) {
				let err = new errors.MessageError("Attaching server", {cause: c.err})
				res.writeHead(500)
				res.end(err.toString())
				return
			}
		} catch (err_) {
			if (res.headersSent) {
				if (!res.writableEnded) {
					res.end()
				}
			} else {
				let err = new errors.MessageError("Internal Server Error", {cause: err_})
				res.writeHead(500)
				res.end(err.toString())
			}
		}
	}

	private async handleMessages(req: express.Request, res: express.Response): Promise<void> {
		try {
			let id = req.headers["mcp-session-id"]

			if (id === undefined || id === "") {
				// https://github.com/modelcontextprotocol/typescript-sdk/blob/1.15.1/src/server/streamableHttp.ts#L587
				let err = new errors.MessageError("Bad Request: Mcp-Session-Id header is required")
				res.writeHead(400)
				res.end(err.toString())
				return
			}

			if (Array.isArray(id)) {
				// https://github.com/modelcontextprotocol/typescript-sdk/blob/1.15.1/src/server/streamableHttp.ts#L597
				let err = new errors.MessageError("Bad Request: Mcp-Session-Id header must be a single value")
				res.writeHead(400)
				res.end(err.toString())
				return
			}

			let r = this.transports.retrieve(id)
			if (r.err) {
				let err = new errors.MessageError("Retrieving transport", {cause: r.err})
				res.writeHead(404)
				res.end(err.toString())
				return
			}

			let h = await result.safeAsync(r.v.handlePostMessage.bind(r.v), req, res)
			if (h.err) {
				// The handlePostMessage will most likely populate the response itself;
				// however, if it does not, we will do it ourselves.
				if (res.headersSent) {
					if (!res.writableEnded) {
						res.end()
					}
				} else {
					let err = new errors.MessageError("Handling post message", {cause: h.err})
					res.writeHead(500)
					res.end(err.toString())
				}
				return
			}
		} catch (err_) {
			if (res.headersSent) {
				if (!res.writableEnded) {
					res.end()
				}
			} else {
				let err = new errors.MessageError("Internal Server Error", {cause: err_})
				res.writeHead(500)
				res.end(err.toString())
			}
		}
	}
}
