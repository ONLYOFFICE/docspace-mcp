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

/**
 * @module
 * @mergeModuleWith mcp
 */

/* eslint-disable typescript/consistent-type-definitions */

import type * as server from "@modelcontextprotocol/sdk/server/index.js"
import type * as streamableHttp from "@modelcontextprotocol/sdk/server/streamableHttp.js"
import * as types from "@modelcontextprotocol/sdk/types.js"
import express from "express"
import * as errors from "../util/errors.ts"
import * as utilExpress from "../util/express.ts"
import * as result from "../util/result.ts"

export type StreamableServerConfig = {
	corsOrigin: string[]
	corsMaxAge: number
	corsAllowedHeaders: string[]
	corsExposedHeaders: string[]
	rateLimitCapacity: number
	rateLimitWindow: number
	handlers: express.Handler[]
	servers: StreamableServerServers
	transports: StreamableServerTransports
}

export type StreamableServerServers = {
	create(req: express.Request): result.Result<server.Server, Error>
}

export type StreamableServerTransports = {
	create(): streamableHttp.StreamableHTTPServerTransport
	retrieve(id: string): result.Result<streamableHttp.StreamableHTTPServerTransport, Error>
}

export class StreamableServer {
	private corsOrigin: string[]
	private corsMaxAge: number
	private corsAllowedHeaders: string[]
	private corsExposedHeaders: string[]
	private rateLimitCapacity: number
	private rateLimitWindow: number
	private handlers: express.Handler[]
	private servers: StreamableServerServers
	private transports: StreamableServerTransports

	constructor(config: StreamableServerConfig) {
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
		// todo: add signal middleware
		// todo: add allowedMethods middleware
		// todo: add supportedMediaTypes middleware

		let cors = (r: express.Router): void => {
			if (this.corsOrigin.length !== 0) {
				let co: utilExpress.CorsOptions = {
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

		let guard = (r: express.Router): void => {
			if (this.rateLimitCapacity && this.rateLimitWindow) {
				let er = new errors.
					JsonrpcError(
						-32000,
						"Too many requests, please try again later",
					).
					toObject()

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

		r.use("/mcp", (() => {
			let r = express.Router()

			r.use(express.json())

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
			let id = req.headers["mcp-session-id"]
			let t: streamableHttp.StreamableHTTPServerTransport | undefined

			if (id === undefined || id === "") {
				if (types.isInitializeRequest(req.body)) {
					let s = this.servers.create(req)
					if (s.err) {
						// It is most likely 400, rather than 500.
						let err = new errors.JsonrpcError(
							-32000,
							"Creating server",
							{cause: s.err},
						)
						res.status(400)
						res.json(err.toObject())
						return
					}

					t = this.transports.create()

					let c = await result.safeAsync(s.v.connect.bind(s.v), t)
					if (c.err) {
						let err = new errors.JsonrpcError(
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
					let err = new errors.JsonrpcError(
						-32000,
						"Bad Request: Mcp-Session-Id header is required",
					)
					res.status(400)
					res.json(err.toObject())
					return
				}
			} else if (Array.isArray(id)) {
				// https://github.com/modelcontextprotocol/typescript-sdk/blob/1.15.1/src/server/streamableHttp.ts#L597
				let err = new errors.JsonrpcError(
					-32000,
					"Bad Request: Mcp-Session-Id header must be a single value",
				)
				res.status(400)
				res.json(err.toObject())
				return
			} else {
				let r = this.transports.retrieve(id)
				if (r.err) {
					let err = new errors.JsonrpcError(
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

			let h = await result.safeAsync(t.handleRequest.bind(t), req, res, req.body)
			if (h.err) {
				// The handleRequest will most likely populate the response itself;
				// however, if it does not, we will do it ourselves.
				if (res.headersSent) {
					if (!res.writableEnded) {
						res.end()
					}
				} else {
					let err = new errors.JsonrpcError(
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
				let err = new errors.JsonrpcError(
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
			let id = req.headers["mcp-session-id"]

			if (id === undefined || id === "") {
				// https://github.com/modelcontextprotocol/typescript-sdk/blob/1.15.1/src/server/streamableHttp.ts#L587
				let err = new errors.JsonrpcError(
					-32000,
					"Bad Request: Mcp-Session-Id header is required",
				)
				res.status(400)
				res.json(err.toObject())
				return
			}

			if (Array.isArray(id)) {
				// https://github.com/modelcontextprotocol/typescript-sdk/blob/1.15.1/src/server/streamableHttp.ts#L597
				let err = new errors.JsonrpcError(
					-32000,
					"Bad Request: Mcp-Session-Id header must be a single value",
				)
				res.status(400)
				res.json(err.toObject())
				return
			}

			let r = this.transports.retrieve(id)
			if (r.err) {
				let err = new errors.JsonrpcError(
					-32001,
					"Retrieving transport",
					{cause: r.err},
				)
				res.status(404)
				res.json(err.toObject())
				return
			}

			let h = await result.safeAsync(r.v.handleRequest.bind(r.v), req, res)
			if (h.err) {
				// The handleRequest will most likely populate the response itself;
				// however, if it does not, we will do it ourselves.
				if (res.headersSent) {
					if (!res.writableEnded) {
						res.end()
					}
				} else {
					let err = new errors.JsonrpcError(
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
				let err = new errors.JsonrpcError(
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
