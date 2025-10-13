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
 * @mergeModuleWith oauth
 */

import * as errors from "@modelcontextprotocol/sdk/server/auth/errors.js"
import * as allowedMethods from "@modelcontextprotocol/sdk/server/auth/middleware/allowedMethods.js"
import * as auth from "@modelcontextprotocol/sdk/shared/auth.js"
import cors from "cors"
import express from "express"
import * as expressRateLimit from "express-rate-limit"
import type * as api from "../api.ts"
import * as utilErrors from "../util/errors.ts"
import * as utilExpress from "../util/express.ts"
import * as result from "../util/result.ts"

export interface AuthServerConfig {
	serverBaseUrl: string
	metadataCorsOrigin: string[]
	metadataCorsMaxAge: number
	metadataRateLimitCapacity: number
	metadataRateLimitWindow: number
	registerCorsOrigin: string[]
	registerCorsMaxAge: number
	registerRateLimitCapacity: number
	registerRateLimitWindow: number
	redirectUris: string[]
	clientId: string
	clientName: string
	scopes: string[]
	tosUri: string
	policyUri: string
	clientSecret: string
	client: AuthServerClient
}

export interface AuthServerClient {
	oauth: AuthServerOauthService
}

export interface AuthServerOauthService {
	metadata(s: AbortSignal): Promise<result.Result<[api.OauthMetadataResponse, api.Response], Error>>
}

class AuthServer {
	private serverBaseUrl: string
	private metadataCorsOrigin: string[]
	private metadataCorsMaxAge: number
	private metadataRateLimitCapacity: number
	private metadataRateLimitWindow: number
	private registerCorsOrigin: string[]
	private registerCorsMaxAge: number
	private registerRateLimitCapacity: number
	private registerRateLimitWindow: number
	private redirectUris: string[]
	private clientId: string
	private clientName: string
	private scopes: string[]
	private tosUri: string
	private policyUri: string
	private clientSecret: string
	private client: AuthServerClient

	constructor(config: AuthServerConfig) {
		this.serverBaseUrl = config.serverBaseUrl
		this.metadataCorsOrigin = config.metadataCorsOrigin
		this.metadataCorsMaxAge = config.metadataCorsMaxAge
		this.metadataRateLimitCapacity = config.metadataRateLimitCapacity
		this.metadataRateLimitWindow = config.metadataRateLimitWindow
		this.registerCorsOrigin = config.registerCorsOrigin
		this.registerCorsMaxAge = config.registerCorsMaxAge
		this.registerRateLimitCapacity = config.registerRateLimitCapacity
		this.registerRateLimitWindow = config.registerRateLimitWindow
		this.redirectUris = config.redirectUris
		this.clientId = config.clientId
		this.clientName = config.clientName
		this.scopes = config.scopes
		this.tosUri = config.tosUri
		this.policyUri = config.policyUri
		this.clientSecret = config.clientSecret
		this.client = config.client
	}

	metadataCors(): express.Handler {
		if (this.metadataCorsOrigin.length === 0) {
			return (_, __, next) => {
				next()
			}
		}

		let o: cors.CorsOptions = {
			origin: this.metadataCorsOrigin,
			methods: ["GET"],
		}

		let exposedHeaders: string[] = []

		if (this.metadataRateLimitCapacity && this.metadataRateLimitWindow) {
			exposedHeaders.push("Retry-After")
		}

		if (exposedHeaders.length !== 0) {
			o.exposedHeaders = exposedHeaders
		}

		if (this.metadataCorsMaxAge) {
			o.maxAge = this.metadataCorsMaxAge / 1000
		}

		return cors(o)
	}

	metadataRateLimit(): express.Handler {
		if (!this.metadataRateLimitCapacity || !this.metadataRateLimitWindow) {
			return (_, __, next) => {
				next()
			}
		}

		return expressRateLimit.rateLimit({
			windowMs: this.metadataRateLimitWindow,
			limit: this.metadataRateLimitCapacity,
			standardHeaders: true,
			legacyHeaders: false,
			message: new errors.
				TooManyRequestsError("You have exceeded the rate limit for authorization server metadata requests").
				toResponseObject(),
		})
	}

	registerCors(): express.Handler {
		if (this.registerCorsOrigin.length === 0) {
			return (_, __, next) => {
				next()
			}
		}

		let o: cors.CorsOptions = {
			origin: this.registerCorsOrigin,
			methods: ["POST"],
			allowedHeaders: ["Content-Type"],
		}

		let exposedHeaders: string[] = []

		if (this.registerRateLimitCapacity && this.registerRateLimitWindow) {
			exposedHeaders.push(
				"Retry-After",
				"RateLimit-Limit",
				"RateLimit-Remaining",
				"RateLimit-Reset",
			)
		}

		if (exposedHeaders.length !== 0) {
			o.exposedHeaders = exposedHeaders
		}

		if (this.registerCorsMaxAge) {
			o.maxAge = this.registerCorsMaxAge / 1000
		}

		return cors(o)
	}

	/**
	 * {@link https://github.com/modelcontextprotocol/typescript-sdk/blob/1.17.0/src/server/auth/handlers/register.ts#L66 | MCP Reference}
	 */
	registerRateLimit(): express.Handler {
		if (!this.registerRateLimitCapacity || !this.registerRateLimitWindow) {
			return (_, __, next) => {
				next()
			}
		}

		return expressRateLimit.rateLimit({
			windowMs: this.registerRateLimitWindow,
			limit: this.registerRateLimitCapacity,
			standardHeaders: true,
			legacyHeaders: false,
			message: new errors.
				TooManyRequestsError("You have exceeded the rate limit for client registration requests").
				toResponseObject(),
		})
	}

	/**
	 * {@link https://github.com/modelcontextprotocol/typescript-sdk/blob/1.17.0/src/client/auth.ts#L616 | MCP Client Reference} \
	 * {@link https://github.com/modelcontextprotocol/typescript-sdk/blob/1.17.0/src/server/auth/handlers/metadata.ts#6 | MCP Server Reference} \
	 * {@link https://datatracker.ietf.org/doc/html/rfc8414#section-3 | RFC 8414 Reference}
	 */
	async metadata(_: express.Request, res: express.Response): Promise<void> {
		let ac = new AbortController()

		let mr = await this.client.oauth.metadata(ac.signal)
		if (mr.err) {
			let err = new utilErrors.OauthError(
				"server_error",
				"Discovering OAuth metadata",
				{cause: mr.err},
			)
			res.status(500)
			res.json(err.toObject())
			return
		}

		let [md] = mr.v

		let pr = auth.OAuthMetadataSchema.safeParse(md)
		if (!pr.success) {
			let err = new utilErrors.OauthError(
				"server_error",
				"Converting OAuth metadata",
				{cause: pr.error},
			)
			res.status(500)
			res.json(err.toObject())
			return
		}

		let ur = result.safeNew(URL, "/register", this.serverBaseUrl)
		if (ur.err) {
			let err = new utilErrors.OauthError(
				"server_error",
				"Creating registration endpoint URL",
				{cause: ur.err},
			)
			res.status(500)
			res.json(err.toObject())
			return
		}

		pr.data.registration_endpoint = ur.v.toString()

		res.status(200)
		res.json(pr.data)
	}

	/**
	 * {@link https://github.com/modelcontextprotocol/typescript-sdk/blob/1.17.0/src/client/auth.ts#L1048 | MCP Client Reference} \
	 * {@link https://github.com/modelcontextprotocol/typescript-sdk/blob/1.17.0/src/server/auth/handlers/register.ts#L45 | MCP Server Reference} \
	 * {@link https://www.rfc-editor.org/rfc/rfc7591#section-3 | RFC 7591 Client Registration Endpoint Reference} \
	 * {@link https://www.rfc-editor.org/rfc/rfc7591#section-2 | RFC 7591 Client Metadata Reference} \
	 * {@link https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1 | RFC 7591 Client Information Response Reference}
	 */
	register(req: express.Request, res: express.Response): void {
		let p = auth.OAuthClientMetadataSchema.safeParse(req.body)
		if (!p.success) {
			let err = new errors.InvalidClientMetadataError(p.error.message)
			res.status(400)
			res.json(err.toResponseObject())
			return
		}

		let m: auth.OAuthClientInformationFull = {
			client_id: this.clientId,
			redirect_uris: this.redirectUris,
		}

		if (this.clientName) {
			m.client_name = this.clientName
		}

		if (this.scopes.length !== 0) {
			m.scope = this.scopes.join(" ")
		}

		if (this.tosUri) {
			m.tos_uri = this.tosUri
		}

		if (this.policyUri) {
			m.policy_uri = this.policyUri
		}

		if (this.clientSecret) {
			m.client_secret = this.clientSecret
		}

		res.status(200)
		res.json(m)
	}
}

export function authServer(config: AuthServerConfig): express.Router {
	let s = new AuthServer(config)

	let r = express.Router()

	r.use("/.well-known/oauth-authorization-server", (() => {
		let r = express.Router()

		r.use(s.metadataCors())
		r.use(allowedMethods.allowedMethods(["GET"]))
		r.use(s.metadataRateLimit())

		r.get("/", s.metadata.bind(s))

		return r
	})())

	r.use("/register", (() => {
		let r = express.Router()

		r.use(express.json())
		r.use(s.registerCors())
		r.use(allowedMethods.allowedMethods(["POST"]))
		r.use(s.registerRateLimit())
		r.use(utilExpress.noCache())

		r.post("/", s.register.bind(s))

		return r
	})())

	return r
}
