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

import type * as server from "@modelcontextprotocol/sdk/server/index.js"
import type * as streamableHttp from "@modelcontextprotocol/sdk/server/streamableHttp.js"
import * as types from "@modelcontextprotocol/sdk/types.js"
import cors from "cors"
import express from "express"
import * as expressRateLimit from "express-rate-limit"
import * as errors from "../util/errors.ts"
import * as result from "../util/result.ts"

export interface StreamableServerConfig {
	corsOrigin: string[]
	corsMaxAge: number
	corsAllowedHeaders: string[]
	corsExposedHeaders: string[]
	rateLimitCapacity: number
	rateLimitWindow: number
	servers: StreamableServerServers
	transports: StreamableServerTransports
}

export interface StreamableServerServers {
	create(req: express.Request): result.Result<server.Server, Error>
}

export interface StreamableServerTransports {
	create(): streamableHttp.StreamableHTTPServerTransport
	retrieve(id: string): result.Result<streamableHttp.StreamableHTTPServerTransport, Error>
}

class StreamableServer {
	private corsOrigin: string[]
	private corsMaxAge: number
	private corsAllowedHeaders: string[]
	private corsExposedHeaders: string[]
	private rateLimitCapacity: number
	private rateLimitWindow: number
	private servers: StreamableServerServers
	private transports: StreamableServerTransports

	constructor(config: StreamableServerConfig) {
		this.corsOrigin = config.corsOrigin
		this.corsMaxAge = config.corsMaxAge
		this.corsAllowedHeaders = config.corsAllowedHeaders
		this.corsExposedHeaders = config.corsExposedHeaders
		this.rateLimitCapacity = config.rateLimitCapacity
		this.rateLimitWindow = config.rateLimitWindow
		this.servers = config.servers
		this.transports = config.transports
	}

	cors(): express.Handler {
		if (this.corsOrigin.length !== 0) {
			return (_, __, next) => {
				next()
			}
		}

		let o: cors.CorsOptions = {
			origin: this.corsOrigin,
			methods: ["GET", "POST", "DELETE"],
			allowedHeaders: [
				...this.corsAllowedHeaders,
				"Content-Type",
				"Mcp-Session-Id",
			],
		}

		let exposedHeaders: string[] = [
			...this.corsExposedHeaders,
			"Mcp-Session-Id",
		]

		if (this.rateLimitCapacity && this.rateLimitWindow) {
			exposedHeaders.push(
				"Retry-After",
				"RateLimit-Limit",
				"RateLimit-Remaining",
				"RateLimit-Reset",
			)
		}

		o.exposedHeaders = exposedHeaders

		if (this.corsMaxAge) {
			o.maxAge = this.corsMaxAge / 1000
		}

		return cors(o)
	}

	rateLimit(): express.Handler {
		if (!this.rateLimitCapacity || !this.rateLimitWindow) {
			return (_, __, next) => {
				next()
			}
		}

		return expressRateLimit.rateLimit({
			windowMs: this.rateLimitWindow,
			limit: this.rateLimitCapacity,
			standardHeaders: true,
			legacyHeaders: false,
			message: new errors.
				JsonrpcError(
					-32000,
					"Too many requests, please try again later",
				).
				toObject(),
		})
	}

	async post(req: express.Request, res: express.Response): Promise<void> {
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

	async get(req: express.Request, res: express.Response): Promise<void> {
		await this.delete(req, res)
	}

	async delete(req: express.Request, res: express.Response): Promise<void> {
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

export function streamableServer(
	config: StreamableServerConfig,
	...handlers: express.RequestHandler[]
): express.Router {
	let s = new StreamableServer(config)

	let r = express.Router()

	r.use("/mcp", ...handlers, (() => {
		let r = express.Router()

		r.use(express.json())
		r.use(s.cors())
		r.use(s.rateLimit())

		r.post("/", s.post.bind(s))
		r.get("/", s.get.bind(s))
		r.delete("/", s.delete.bind(s))

		return r
	})())

	return r
}
