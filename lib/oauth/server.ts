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

/* eslint-disable typescript/consistent-type-definitions */

import contentType from "content-type"
import cors from "cors"
import express from "express"
import * as expressRateLimit from "express-rate-limit"
import jwt from "jsonwebtoken"
import * as errors from "../util/errors.ts"
import * as utilExpress from "../util/express.ts"
import * as r from "../util/result.ts"
import type {AuthTokenPayload} from "./auth.ts"
import {InvalidAuthTokenError} from "./auth.ts"
import type {ClientResponse} from "./client.ts"
import {ClientErrorResponse} from "./client.ts"
import type {
	AuthorizeRequest,
	AuthorizeResponse,
	ErrorResponse,
	IntrospectRequest,
	IntrospectResponse,
	RegisterResponse,
	ResourceMetadataResponse,
	RevokeRequest,
	ServerMetadataResponse,
	TokenRequest,
	TokenResponse,
} from "./shared.ts"
import {
	AuthorizeRequestSchema,
	AuthorizeResponseSchema,
	IntrospectRequestSchema,
	RevokeRequestSchema,
	TokenRequestSchema,
} from "./shared.ts"
import type {State} from "./state.ts"
import {InvalidStateTokenError} from "./state.ts"

declare module "express-serve-static-core" {
	interface Request {
		oauth?: ExpressOauth
	}
}

type ExpressOauth = {
	aud: string
	token: string
}

export type ServerConfig = {
	baseUrl: string
	scopes: string[]
	clientId: string
	clientSecret: string
	serverMetadataCorsOrigin: string[]
	serverMetadataCorsMaxAge: number
	serverMetadataRateLimitCapacity: number
	serverMetadataRateLimitWindow: number
	resourceMetadataCorsOrigin: string[]
	resourceMetadataCorsMaxAge: number
	resourceMetadataRateLimitCapacity: number
	resourceMetadataRateLimitWindow: number
	authorizeCorsOrigin: string[]
	authorizeCorsMaxAge: number
	authorizeRateLimitCapacity: number
	authorizeRateLimitWindow: number
	callbackCorsOrigin: string[]
	callbackCorsMaxAge: number
	callbackRateLimitCapacity: number
	callbackRateLimitWindow: number
	introspectCorsOrigin: string[]
	introspectCorsMaxAge: number
	introspectRateLimitCapacity: number
	introspectRateLimitWindow: number
	registerCorsOrigin: string[]
	registerCorsMaxAge: number
	registerRateLimitCapacity: number
	registerRateLimitWindow: number
	revokeCorsOrigin: string[]
	revokeCorsMaxAge: number
	revokeRateLimitCapacity: number
	revokeRateLimitWindow: number
	tokenCorsOrigin: string[]
	tokenCorsMaxAge: number
	tokenRateLimitCapacity: number
	tokenRateLimitWindow: number
	client: ServerClient
	authTokens: ServerAuthTokens
	stateTokens: ServerStateTokens
}

export type ServerClient = {
	authorize(o: AuthorizeRequest): r.Result<URL, Error>
	introspect(s: AbortSignal | undefined, o: IntrospectRequest): Promise<r.Result<[IntrospectResponse, ClientResponse], Error>>
	revoke(s: AbortSignal | undefined, o: RevokeRequest): Promise<r.Result<ClientResponse, Error>>
	token(s: AbortSignal | undefined, o: TokenRequest): Promise<r.Result<[TokenResponse, ClientResponse], Error>>
}

export type ServerAuthTokens = {
	decode(t: string): r.Result<[string, AuthTokenPayload], Error>
	encode(t: string): r.Result<[string, AuthTokenPayload], Error>
}

export type ServerStateTokens = {
	decode(t: string): r.Result<State, Error>
	encode(s: State): r.Result<string, Error>
}

export class Server {
	private clientId: string
	private clientSecret: string
	private serverMetadataCorsOrigin: string[]
	private serverMetadataCorsMaxAge: number
	private serverMetadataRateLimitCapacity: number
	private serverMetadataRateLimitWindow: number
	private resourceMetadataCorsOrigin: string[]
	private resourceMetadataCorsMaxAge: number
	private resourceMetadataRateLimitCapacity: number
	private resourceMetadataRateLimitWindow: number
	private authorizeCorsOrigin: string[]
	private authorizeCorsMaxAge: number
	private authorizeRateLimitCapacity: number
	private authorizeRateLimitWindow: number
	private callbackCorsOrigin: string[]
	private callbackCorsMaxAge: number
	private callbackRateLimitCapacity: number
	private callbackRateLimitWindow: number
	private introspectCorsOrigin: string[]
	private introspectCorsMaxAge: number
	private introspectRateLimitCapacity: number
	private introspectRateLimitWindow: number
	private registerCorsOrigin: string[]
	private registerCorsMaxAge: number
	private registerRateLimitCapacity: number
	private registerRateLimitWindow: number
	private revokeCorsOrigin: string[]
	private revokeCorsMaxAge: number
	private revokeRateLimitCapacity: number
	private revokeRateLimitWindow: number
	private tokenCorsOrigin: string[]
	private tokenCorsMaxAge: number
	private tokenRateLimitCapacity: number
	private tokenRateLimitWindow: number

	private client: ServerClient
	private authTokens: ServerAuthTokens
	private stateTokens: ServerStateTokens

	private baseUrl: string
	private resourceMetadataUrl: string
	private authorizeUrl: string
	private callbackUrl: string
	private introspectUrl: string
	private registerUrl: string
	private revokeUrl: string
	private tokenUrl: string
	private scope: string

	constructor(config: ServerConfig) {
		this.clientId = config.clientId
		this.clientSecret = config.clientSecret
		this.serverMetadataCorsOrigin = config.serverMetadataCorsOrigin
		this.serverMetadataCorsMaxAge = config.serverMetadataCorsMaxAge
		this.serverMetadataRateLimitCapacity = config.serverMetadataRateLimitCapacity
		this.serverMetadataRateLimitWindow = config.serverMetadataRateLimitWindow
		this.resourceMetadataCorsOrigin = config.resourceMetadataCorsOrigin
		this.resourceMetadataCorsMaxAge = config.resourceMetadataCorsMaxAge
		this.resourceMetadataRateLimitCapacity = config.resourceMetadataRateLimitCapacity
		this.resourceMetadataRateLimitWindow = config.resourceMetadataRateLimitWindow
		this.authorizeCorsOrigin = config.authorizeCorsOrigin
		this.authorizeCorsMaxAge = config.authorizeCorsMaxAge
		this.authorizeRateLimitCapacity = config.authorizeRateLimitCapacity
		this.authorizeRateLimitWindow = config.authorizeRateLimitWindow
		this.callbackCorsOrigin = config.callbackCorsOrigin
		this.callbackCorsMaxAge = config.callbackCorsMaxAge
		this.callbackRateLimitCapacity = config.callbackRateLimitCapacity
		this.callbackRateLimitWindow = config.callbackRateLimitWindow
		this.introspectCorsOrigin = config.introspectCorsOrigin
		this.introspectCorsMaxAge = config.introspectCorsMaxAge
		this.introspectRateLimitCapacity = config.introspectRateLimitCapacity
		this.introspectRateLimitWindow = config.introspectRateLimitWindow
		this.registerCorsOrigin = config.registerCorsOrigin
		this.registerCorsMaxAge = config.registerCorsMaxAge
		this.registerRateLimitCapacity = config.registerRateLimitCapacity
		this.registerRateLimitWindow = config.registerRateLimitWindow
		this.revokeCorsOrigin = config.revokeCorsOrigin
		this.revokeCorsMaxAge = config.revokeCorsMaxAge
		this.revokeRateLimitCapacity = config.revokeRateLimitCapacity
		this.revokeRateLimitWindow = config.revokeRateLimitWindow
		this.tokenCorsOrigin = config.tokenCorsOrigin
		this.tokenCorsMaxAge = config.tokenCorsMaxAge
		this.tokenRateLimitCapacity = config.tokenRateLimitCapacity
		this.tokenRateLimitWindow = config.tokenRateLimitWindow

		this.client = config.client
		this.authTokens = config.authTokens
		this.stateTokens = config.stateTokens

		let pb = r.safeNew(URL, "/", config.baseUrl)
		if (pb.err) {
			throw new Error("Creating base URL", {cause: pb.v})
		}

		let pr = r.safeNew(URL, "/.well-known/oauth-protected-resource", config.baseUrl)
		if (pr.err) {
			throw new Error("Creating resource metadata URL", {cause: pr.err})
		}

		let pa = r.safeNew(URL, "/oauth/authorize", config.baseUrl)
		if (pa.err) {
			throw new Error("Creating authorize URL", {cause: pa.err})
		}

		let pc = r.safeNew(URL, "/oauth/callback", config.baseUrl)
		if (pc.err) {
			throw new Error("Creating callback URL", {cause: pc.err})
		}

		let pi = r.safeNew(URL, "/oauth/introspect", config.baseUrl)
		if (pi.err) {
			throw new Error("Creating introspect URL", {cause: pi.err})
		}

		let pg = r.safeNew(URL, "/oauth/register", config.baseUrl)
		if (pg.err) {
			throw new Error("Creating register URL", {cause: pg.err})
		}

		let pv = r.safeNew(URL, "/oauth/revoke", config.baseUrl)
		if (pv.err) {
			throw new Error("Creating register URL", {cause: pv.err})
		}

		let pt = r.safeNew(URL, "/oauth/token", config.baseUrl)
		if (pt.err) {
			throw new Error("Creating token URL", {cause: pt.err})
		}

		let bu: string | undefined

		if (pb.v.pathname === "/") {
			bu = pb.v.href.slice(0, -1)
		} else {
			bu = pb.v.href
		}

		this.baseUrl = bu
		this.resourceMetadataUrl = pr.v.href
		this.authorizeUrl = pa.v.href
		this.callbackUrl = pc.v.href
		this.introspectUrl = pi.v.href
		this.registerUrl = pg.v.href
		this.revokeUrl = pv.v.href
		this.tokenUrl = pt.v.href
		this.scope = config.scopes.join(" ")
	}

	router(): express.Router {
		let r = express.Router()

		r.use(utilExpress.signal())
		r.use(express.json())
		r.use(express.urlencoded({extended: true}))

		r.use("/.well-known/oauth-authorization-server", (() => {
			let r = express.Router()

			r.use(allowedMethods(["GET"]))

			if (this.serverMetadataCorsOrigin.length !== 0) {
				let co: CrossOriginOptions = {
					origin: this.serverMetadataCorsOrigin,
					maxAge: this.serverMetadataCorsMaxAge,
					methods: ["GET"],
					allowedHeaders: [],
					capacity: this.serverMetadataRateLimitCapacity,
					window: this.serverMetadataRateLimitWindow,
				}

				r.use(crossOrigin(co))
			}

			if (this.serverMetadataRateLimitCapacity && this.serverMetadataRateLimitWindow) {
				let ro: RateLimitOptions = {
					capacity: this.serverMetadataRateLimitCapacity,
					window: this.serverMetadataRateLimitWindow,
				}

				r.use(rateLimit(ro))
			}

			r.use(this.handleServerMetadata.bind(this))

			return r
		})())

		r.use("/.well-known/oauth-protected-resource", (() => {
			let r = express.Router()

			r.use(allowedMethods(["GET"]))

			if (this.resourceMetadataCorsOrigin.length !== 0) {
				let co: CrossOriginOptions = {
					origin: this.resourceMetadataCorsOrigin,
					maxAge: this.resourceMetadataCorsMaxAge,
					methods: ["GET"],
					allowedHeaders: [],
					capacity: this.resourceMetadataRateLimitCapacity,
					window: this.resourceMetadataRateLimitWindow,
				}

				r.use(crossOrigin(co))
			}

			if (this.resourceMetadataRateLimitCapacity && this.resourceMetadataRateLimitWindow) {
				let ro: RateLimitOptions = {
					capacity: this.resourceMetadataRateLimitCapacity,
					window: this.resourceMetadataRateLimitWindow,
				}

				r.use(rateLimit(ro))
			}

			r.use(this.handleResourceMetadata.bind(this))

			return r
		})())

		r.use("/oauth/authorize", (() => {
			let r = express.Router()

			r.use(allowedMethods(["GET"]))

			if (this.authorizeCorsOrigin.length !== 0) {
				let co: CrossOriginOptions = {
					origin: this.authorizeCorsOrigin,
					maxAge: this.authorizeCorsMaxAge,
					methods: ["GET"],
					allowedHeaders: [],
					capacity: this.authorizeRateLimitCapacity,
					window: this.authorizeRateLimitWindow,
				}

				r.use(crossOrigin(co))
			}

			if (this.authorizeRateLimitCapacity && this.authorizeRateLimitWindow) {
				let ro: RateLimitOptions = {
					capacity: this.authorizeRateLimitCapacity,
					window: this.authorizeRateLimitWindow,
				}

				r.use(rateLimit(ro))
			}

			r.use(this.handleAuthorize.bind(this))

			return r
		})())

		r.use("/oauth/callback", (() => {
			let r = express.Router()

			r.use(allowedMethods(["GET"]))

			if (this.callbackCorsOrigin.length !== 0) {
				let co: CrossOriginOptions = {
					origin: this.callbackCorsOrigin,
					maxAge: this.callbackCorsMaxAge,
					methods: ["GET"],
					allowedHeaders: [],
					capacity: this.callbackRateLimitCapacity,
					window: this.callbackRateLimitWindow,
				}

				r.use(crossOrigin(co))
			}

			if (this.callbackRateLimitCapacity && this.callbackRateLimitWindow) {
				let ro: RateLimitOptions = {
					capacity: this.callbackRateLimitCapacity,
					window: this.callbackRateLimitWindow,
				}

				r.use(rateLimit(ro))
			}

			r.use(this.handleCallback.bind(this))

			return r
		})())

		r.use("/oauth/introspect", (() => {
			let r = express.Router()

			r.use(allowedMethods(["POST"]))
			r.use(supportedMediaTypes(["application/x-www-form-urlencoded"]))

			if (this.introspectCorsOrigin.length !== 0) {
				let co: CrossOriginOptions = {
					origin: this.introspectCorsOrigin,
					maxAge: this.introspectCorsMaxAge,
					methods: ["POST"],
					allowedHeaders: ["Content-Type"],
					capacity: this.introspectRateLimitCapacity,
					window: this.introspectRateLimitWindow,
				}

				r.use(crossOrigin(co))
			}

			if (this.introspectRateLimitCapacity && this.introspectRateLimitWindow) {
				let ro: RateLimitOptions = {
					capacity: this.introspectRateLimitCapacity,
					window: this.introspectRateLimitWindow,
				}

				r.use(rateLimit(ro))
			}

			r.use(this.handleIntrospect.bind(this))

			return r
		})())

		r.use("/oauth/register", (() => {
			let r = express.Router()

			r.use(allowedMethods(["POST"]))
			r.use(supportedMediaTypes(["application/json"]))

			if (this.registerCorsOrigin.length !== 0) {
				let co: CrossOriginOptions = {
					origin: this.registerCorsOrigin,
					maxAge: this.registerCorsMaxAge,
					methods: ["POST"],
					allowedHeaders: ["Content-Type"],
					capacity: this.registerRateLimitCapacity,
					window: this.registerRateLimitWindow,
				}

				r.use(crossOrigin(co))
			}

			if (this.registerRateLimitCapacity && this.registerRateLimitWindow) {
				let ro: RateLimitOptions = {
					capacity: this.registerRateLimitCapacity,
					window: this.registerRateLimitWindow,
				}

				r.use(rateLimit(ro))
			}

			r.use(this.handleRegister.bind(this))

			return r
		})())

		r.use("/oauth/revoke", (() => {
			let r = express.Router()

			r.use(allowedMethods(["POST"]))
			r.use(supportedMediaTypes(["application/x-www-form-urlencoded"]))

			if (this.revokeCorsOrigin.length !== 0) {
				let co: CrossOriginOptions = {
					origin: this.revokeCorsOrigin,
					maxAge: this.revokeCorsMaxAge,
					methods: ["POST"],
					allowedHeaders: ["Content-Type"],
					capacity: this.revokeRateLimitCapacity,
					window: this.revokeRateLimitWindow,
				}

				r.use(crossOrigin(co))
			}

			if (this.revokeRateLimitCapacity && this.revokeRateLimitWindow) {
				let ro: RateLimitOptions = {
					capacity: this.revokeRateLimitCapacity,
					window: this.revokeRateLimitWindow,
				}

				r.use(rateLimit(ro))
			}

			r.use(this.handleRevoke.bind(this))

			return r
		})())

		r.use("/oauth/token", (() => {
			let r = express.Router()

			r.use(allowedMethods(["POST"]))
			r.use(supportedMediaTypes(["application/x-www-form-urlencoded"]))

			if (this.tokenCorsOrigin.length !== 0) {
				let co: CrossOriginOptions = {
					origin: this.tokenCorsOrigin,
					maxAge: this.tokenCorsMaxAge,
					methods: ["POST"],
					allowedHeaders: ["Content-Type"],
					capacity: this.tokenRateLimitCapacity,
					window: this.tokenRateLimitWindow,
				}

				r.use(crossOrigin(co))
			}

			if (this.tokenRateLimitCapacity && this.tokenRateLimitWindow) {
				let ro: RateLimitOptions = {
					capacity: this.tokenRateLimitCapacity,
					window: this.tokenRateLimitWindow,
				}

				r.use(rateLimit(ro))
			}

			r.use(this.handleToken.bind(this))

			return r
		})())

		return r
	}

	/**
	 * {@link https://www.rfc-editor.org/rfc/rfc6750.html#section-3 | RFC 6750 Reference}
	 */
	handler(): express.RequestHandler {
		let www = (e: ErrorResponse): string => {
			let s = `Bearer error="${e.error}", `

			if (e.error_description) {
				s += `error_description=${JSON.stringify(e.error_description)}, `
			}

			if (e.error_uri) {
				s += `error_uri="${e.error_uri}", `
			}

			s += `resource_metadata="${this.resourceMetadataUrl}"`

			return s
		}

		return async(req, res, next) => {
			let ih = parseAuth("bearer", req)
			if (ih.err) {
				let err = new Error("Parsing header", {cause: ih.err})
				let er: ErrorResponse = {
					error: "invalid_request",
					error_description: errors.format(err),
				}
				res.set("WWW-Authenticate", www(er))
				res.status(401)
				res.json(er)
				return
			}

			let tu = this.authTokens.decode(ih.v)
			if (tu.err) {
				let err = new Error("Decoding token", {cause: tu.err})

				let code: number | undefined
				let error: string | undefined

				if (errors.as(tu.err, InvalidAuthTokenError)) {
					code = 401
					error = "invalid_token"
				} else {
					code = 500
					error = "server_error"
				}

				let er: ErrorResponse = {
					error,
					error_description: errors.format(err),
				}
				res.status(code)
				res.json(er)
				return
			}

			let [tt, tp] = tu.v

			if (!tp.pld.aud) {
				let err = new Error("No audience")
				let er: ErrorResponse = {
					error: "server_error",
					error_description: errors.format(err),
				}
				res.status(500)
				res.json(er)
				return
			}

			if (!(typeof tp.pld.aud === "string")) {
				let err = new Error("Invalid audience")
				let er: ErrorResponse = {
					error: "server_error",
					error_description: errors.format(err),
				}
				res.status(500)
				res.json(er)
				return
			}

			let io: IntrospectRequest = {
				token: tt,
			}

			let ci = await this.client.introspect(req.signal, io)
			if (ci.err) {
				let err = new Error("Introspecting token", {cause: ci.err})
				let [co, er] = proxyError(ci.err, err)
				res.set("WWW-Authenticate", www(er))
				res.status(co)
				res.json(er)
				return
			}

			let [id] = ci.v

			if (!id.active) {
				let err = new Error("Inactive token")
				let er: ErrorResponse = {
					error: "invalid_token",
					error_description: errors.format(err),
				}
				res.set("WWW-Authenticate", www(er))
				res.status(401)
				res.json(er)
				return
			}

			if (id.exp && id.exp < Math.floor(Date.now() / 1000)) {
				let err = new Error("Expired token")
				let er: ErrorResponse = {
					error: "invalid_token",
					error_description: errors.format(err),
				}
				res.set("WWW-Authenticate", www(er))
				res.status(401)
				res.json(er)
				return
			}

			req.oauth = {
				aud: tp.pld.aud,
				token: tt,
			}

			next()
		}
	}

	/**
	 * {@link https://www.rfc-editor.org/rfc/rfc8414#section-3 | RFC 8414 Reference}
	 */
	private handleServerMetadata(_: express.Request, res: express.Response): void {
		let ob: ServerMetadataResponse = {
			issuer: this.baseUrl,
			authorization_endpoint: this.authorizeUrl,
			token_endpoint: this.tokenUrl,
			registration_endpoint: this.registerUrl,
			response_types_supported: [
				"code",
			],
			grant_types_supported: [
				"authorization_code",
				"refresh_token",
			],
			token_endpoint_auth_methods_supported: [
				"client_secret_basic",
				"client_secret_post",
			],
			revocation_endpoint: this.revokeUrl,
			revocation_endpoint_auth_methods_supported: [
				"client_secret_basic",
				"client_secret_post",
			],
			introspection_endpoint: this.introspectUrl,
			introspection_endpoint_auth_methods_supported: [
				"client_secret_basic",
				"client_secret_post",
			],
			code_challenge_methods_supported: [
				"S256",
			],
		}
		res.status(200)
		res.json(ob)
	}

	/**
	 * {@link https://www.rfc-editor.org/rfc/rfc9728#name-obtaining-protected-resourc | RFC 9728 Reference}
	 */
	private handleResourceMetadata(_: express.Request, res: express.Response): void {
		let ob: ResourceMetadataResponse = {
			resource: this.baseUrl,
			authorization_servers: [
				this.authorizeUrl,
			],
			bearer_methods_supported: [
				"header",
			],
		}
		res.status(200)
		res.json(ob)
	}

	/**
	 * {@link https://www.rfc-editor.org/rfc/rfc6749#section-3.1 | RFC 6749 Reference}
	 */
	private handleAuthorize(req: express.Request, res: express.Response): void {
		let iq = AuthorizeRequestSchema.safeParse(req.query)
		if (!iq.success) {
			let err = new Error("Parsing query", {cause: iq.error})
			let er: ErrorResponse = {
				error: "invalid_request",
				error_description: errors.format(err),
			}
			res.status(400)
			res.json(er)
			return
		}

		if (!iq.data.redirect_uri) {
			let err = new Error("No redirect URI")
			let er: ErrorResponse = {
				error: "invalid_request",
				error_description: errors.format(err),
			}
			res.status(400)
			res.json(er)
			return
		}

		let st: State = {
			redirect_uri: iq.data.redirect_uri,
		}

		if (iq.data.state) {
			st.state = iq.data.state
		}

		let se = this.stateTokens.encode(st)
		if (se.err) {
			let err = new Error("Encoding token", {cause: se.err})
			let er: ErrorResponse = {
				error: "server_error",
				error_description: errors.format(err),
			}
			res.status(500)
			res.json(er)
			return
		}

		let ao: AuthorizeRequest = {
			response_type: "code",
			client_id: iq.data.client_id,
			redirect_uri: this.callbackUrl,
			scope: this.scope,
			state: se.v,
		}

		let ca = this.client.authorize(ao)
		if (ca.err) {
			let err = new Error("Creating authorization URL", {cause: ca.err})
			let [co, er] = proxyError(ca.err, err)
			res.status(co)
			res.json(er)
			return
		}

		res.redirect(ca.v.href)
	}

	/**
	 * {@link https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2 | RFC 6749 Reference}
	 */
	private handleCallback(req: express.Request, res: express.Response): void {
		let iq = AuthorizeResponseSchema.safeParse(req.query)
		if (!iq.success) {
			let err = new Error("Parsing query", {cause: iq.error})
			let er: ErrorResponse = {
				error: "invalid_request",
				error_description: errors.format(err),
			}
			res.status(400)
			res.json(er)
			return
		}

		if (!iq.data.state) {
			let err = new Error("No state", {cause: iq.error})
			let er: ErrorResponse = {
				error: "invalid_request",
				error_description: errors.format(err),
			}
			res.status(400)
			res.json(er)
			return
		}

		let sd = this.stateTokens.decode(iq.data.state)
		if (sd.err) {
			let err = new Error("Decoding token", {cause: sd.err})

			let code: number | undefined
			let error: string | undefined

			if (errors.as(sd.err, InvalidStateTokenError)) {
				code = 400
				error = "invalid_request"
			} else {
				code = 500
				error = "server_error"
			}

			let er: ErrorResponse = {
				error,
				error_description: errors.format(err),
			}
			res.status(code)
			res.json(er)
			return
		}

		let oq: AuthorizeResponse = {
			code: iq.data.code,
		}

		if (sd.v.state) {
			oq.state = sd.v.state
		}

		let op = new URLSearchParams(oq)

		let ou = new URL(sd.v.redirect_uri)

		ou.search = op.toString()

		res.redirect(ou.href)
	}

	/**
	 * {@link https://www.rfc-editor.org/rfc/rfc7662#section-2 | RFC 7662 Reference}
	 */
	private async handleIntrospect(req: express.Request, res: express.Response): Promise<void> {
		let ih = parseAuth("basic", req)
		if (ih.err) {
			if (ih.err.message !== "No header") {
				let err = new Error("Parsing header", {cause: ih.err})
				let er: ErrorResponse = {
					error: "invalid_request",
					error_description: errors.format(err),
				}
				res.status(400)
				res.json(er)
				return
			}
			ih = r.ok("")
		}

		let ib = IntrospectRequestSchema.safeParse(req.body)
		if (!ib.success) {
			let err = new Error("Parsing body", {cause: ib.error})
			let er: ErrorResponse = {
				error: "invalid_request",
				error_description: errors.format(err),
			}
			res.status(400)
			res.json(er)
			return
		}

		if (!ih.v && !ib.data.token) {
			let err = new Error("No token")
			let er: ErrorResponse = {
				error: "invalid_request",
				error_description: errors.format(err),
			}
			res.status(400)
			res.json(er)
			return
		}

		if (ih.v && ib.data.token && ih.v !== ib.data.token) {
			let err = new Error("Mismatched tokens")
			let er: ErrorResponse = {
				error: "invalid_request",
				error_description: errors.format(err),
			}
			res.status(400)
			res.json(er)
			return
		}

		let it: string | undefined

		if (ih.v) {
			it = ih.v
		} else if (ib.data.token) {
			it = ib.data.token
		} else {
			it = "" // unreachable
		}

		let tu = this.authTokens.decode(it)
		if (tu.err) {
			if (
				errors.as(tu.err, jwt.NotBeforeError) ||
				errors.as(tu.err, jwt.TokenExpiredError)
			) {
				let ob: IntrospectResponse = {
					active: false,
				}
				res.status(200)
				res.json(ob)
				return
			}

			let err = new Error("Decoding token", {cause: tu.err})

			let code: number | undefined
			let error: string | undefined

			if (errors.as(tu.err, InvalidAuthTokenError)) {
				code = 401
				error = "invalid_token"
			} else {
				code = 500
				error = "server_error"
			}

			let er: ErrorResponse = {
				error,
				error_description: errors.format(err),
			}
			res.status(code)
			res.json(er)
			return
		}

		let [tt, tp] = tu.v

		let io: IntrospectRequest = {
			token: tt,
		}

		let ci = await this.client.introspect(req.signal, io)
		if (ci.err) {
			let err = new Error("Introspecting token", {cause: ci.err})
			let [co, er] = proxyError(ci.err, err)
			res.status(co)
			res.json(er)
			return
		}

		let [id] = ci.v

		let ob: IntrospectResponse = {
			active: id.active,
		}

		if (ob.active) {
			if (id.exp && tp.exp) {
				ob.exp = Math.min(id.exp, tp.exp)
			} else if (id.exp) {
				ob.exp = id.exp
			} else if (tp.exp) {
				ob.exp = tp.exp
			}
		}

		res.status(200)
		res.json(ob)
	}

	/**
	 * {@link https://www.rfc-editor.org/rfc/rfc7591#section-3 | RFC 7591 Reference}
	 */
	private handleRegister(_: express.Request, res: express.Response): void {
		let ob: RegisterResponse = {
			client_id: this.clientId,
			client_secret: this.clientSecret,
		}
		res.status(201)
		res.json(ob)
	}

	/**
	 * {@link https://www.rfc-editor.org/rfc/rfc7009#section-2 | RFC 7009 Reference}
	 */
	private async handleRevoke(req: express.Request, res: express.Response): Promise<void> {
		let ih = parseAuth("basic", req)
		if (ih.err) {
			if (ih.err.message !== "No header") {
				let err = new Error("Parsing header", {cause: ih.err})
				let er: ErrorResponse = {
					error: "invalid_request",
					error_description: errors.format(err),
				}
				res.status(400)
				res.json(er)
				return
			}
			ih = r.ok("")
		}

		let ib = RevokeRequestSchema.safeParse(req.body)
		if (!ib.success) {
			let err = new Error("Parsing body", {cause: ib.error})
			let er: ErrorResponse = {
				error: "invalid_request",
				error_description: errors.format(err),
			}
			res.status(400)
			res.json(er)
			return
		}

		if (!ih.v && !ib.data.token) {
			let err = new Error("No token")
			let er: ErrorResponse = {
				error: "invalid_request",
				error_description: errors.format(err),
			}
			res.status(400)
			res.json(er)
			return
		}

		if (ih.v && ib.data.token && ih.v !== ib.data.token) {
			let err = new Error("Mismatched tokens")
			let er: ErrorResponse = {
				error: "invalid_request",
				error_description: errors.format(err),
			}
			res.status(400)
			res.json(er)
			return
		}

		let it: string | undefined

		if (ih.v) {
			it = ih.v
		} else if (ib.data.token) {
			it = ib.data.token
		} else {
			it = "" // unreachable
		}

		let ro: RevokeRequest = {
			token: it,
		}

		if (ib.data.token_type_hint) {
			ro.token_type_hint = ib.data.token_type_hint
		}

		let cr = await this.client.revoke(req.signal, ro)
		if (cr.err) {
			let err = new Error("Revoking token", {cause: cr.err})
			let [co, er] = proxyError(cr.err, err)
			res.status(co)
			res.json(er)
			return
		}

		res.status(200)
		res.end()
	}

	/**
	 * {@link https://www.rfc-editor.org/rfc/rfc6749#section-3.2 | RFC 6749 Reference}
	 */
	private async handleToken(req: express.Request, res: express.Response): Promise<void> {
		let ih = parseAuth("basic", req)
		if (ih.err) {
			if (ih.err.message !== "No header") {
				let err = new Error("Parsing header", {cause: ih.err})
				let er: ErrorResponse = {
					error: "invalid_request",
					error_description: errors.format(err),
				}
				res.status(400)
				res.json(er)
				return
			}
			ih = r.ok("")
		}

		let ib = TokenRequestSchema.safeParse(req.body)
		if (!ib.success) {
			let err = new Error("Parsing body", {cause: ib.error})
			let er: ErrorResponse = {
				error: "invalid_request",
				error_description: errors.format(err),
			}
			res.status(400)
			res.json(er)
			return
		}

		let ht = ih.v
		let bt: string | undefined

		switch (ib.data.grant_type) {
		case "authorization_code":
			bt = ib.data.client_secret
			break

		case "refresh_token":
			bt = ib.data.refresh_token
			break
		}

		if (!ht && !bt) {
			let err = new Error("No token")
			let er: ErrorResponse = {
				error: "invalid_request",
				error_description: errors.format(err),
			}
			res.status(400)
			res.json(er)
			return
		}

		if (ht && bt && ht !== bt) {
			let err = new Error("Mismatched tokens")
			let er: ErrorResponse = {
				error: "invalid_request",
				error_description: errors.format(err),
			}
			res.status(400)
			res.json(er)
			return
		}

		let it: string | undefined

		if (ht) {
			it = ht
		} else if (bt) {
			it = bt
		} else {
			it = "" // unreachable
		}

		let to: TokenRequest | undefined

		switch (ib.data.grant_type) {
		case "authorization_code":
			to = {
				grant_type: ib.data.grant_type,
				code: ib.data.code,
				redirect_uri: this.callbackUrl,
				client_id: ib.data.client_id,
				client_secret: it,
			}
			break

		case "refresh_token":
			to = {
				grant_type: ib.data.grant_type,
				refresh_token: it,
			}
			break
		}

		let ct = await this.client.token(req.signal, to)
		if (ct.err) {
			let err = new Error("Requesting token", {cause: ct.err})
			let [co, er] = proxyError(ct.err, err)
			res.status(co)
			res.json(er)
			return
		}

		let [td] = ct.v

		let tw = this.authTokens.encode(td.access_token)
		if (tw.err) {
			let err = new Error("Encoding token", {cause: tw.err})
			let er: ErrorResponse = {
				error: "server_error",
				error_description: errors.format(err),
			}
			res.status(500)
			res.json(er)
			return
		}

		let [tt, tp] = tw.v

		let ob: TokenResponse = {
			access_token: tt,
			token_type: td.token_type,
		}

		if (td.refresh_token) {
			ob.refresh_token = td.refresh_token
		}

		if (td.expires_in && tp.exp) {
			ob.expires_in = Math.min(td.expires_in, tp.exp - tp.iat)
		} else if (td.expires_in) {
			ob.expires_in = td.expires_in
		} else if (tp.exp) {
			ob.expires_in = tp.exp
		}

		res.status(200)
		res.json(ob)
	}
}

function allowedMethods(methods: string[]): express.Handler {
	let am = methods.join(", ")

	return (req, res, next) => {
		if (methods.includes(req.method)) {
			next()
			return
		}

		let er: ErrorResponse = {
			error: "invalid_request",
			error_description: "Method Not Allowed",
		}
		res.status(405)
		res.set("Allow", am)
		res.json(er)
	}
}

function supportedMediaTypes(types: string[]): express.Handler {
	let st = types.join(", ")

	return (req, res, next) => {
		let ct = r.safeSync(contentType.parse, req)
		if (!ct.err && types.includes(ct.v.type)) {
			next()
			return
		}

		let er: ErrorResponse = {
			error: "invalid_request",
			error_description: "Unsupported Media Type",
		}
		res.status(415)
		res.set("Accept", st)
		res.json(er)
	}
}

type CrossOriginOptions = {
	origin: string[]
	maxAge: number
	methods: string[]
	allowedHeaders: string[]
	capacity: number
	window: number
}

function crossOrigin(o: CrossOriginOptions): express.Handler {
	let co: cors.CorsOptions = {}

	if (o.origin.length !== 0) {
		co.origin = o.origin
	}

	if (o.methods.length !== 0) {
		co.methods = o.methods
	}

	if (o.allowedHeaders.length !== 0) {
		co.allowedHeaders = o.allowedHeaders
	}

	let exposedHeaders: string[] = []

	if (o.capacity && o.window) {
		exposedHeaders.push(
			"Retry-After",
			"RateLimit-Limit",
			"RateLimit-Remaining",
			"RateLimit-Reset",
		)
	}

	if (exposedHeaders.length !== 0) {
		co.exposedHeaders = exposedHeaders
	}

	if (o.maxAge) {
		co.maxAge = o.maxAge / 1000
	}

	return cors(co)
}

type RateLimitOptions = {
	capacity: number
	window: number
}

function rateLimit(o: RateLimitOptions): express.Handler {
	let er: ErrorResponse = {
		error: "too_many_requests",
		error_description: "Too Many Requests",
	}

	let ro: Partial<expressRateLimit.Options> = {
		windowMs: o.window,
		limit: o.capacity,
		standardHeaders: true,
		legacyHeaders: false,
		message: er,
	}

	return expressRateLimit.rateLimit(ro)
}

function parseAuth(scheme: string, req: express.Request): r.Result<string, Error> {
	let h = req.headers.authorization

	if (!h) {
		return r.error(new Error("No header"))
	}

	let parts = h.split(" ")

	if (parts.length !== 2) {
		return r.error(new Error("Malformed header"))
	}

	let s = parts[0]

	if (!s) {
		return r.error(new Error("No scheme"))
	}

	if (s.toLowerCase() !== scheme) {
		return r.error(new Error("Invalid scheme"))
	}

	let t = parts[1]

	if (!t) {
		return r.error(new Error("No token"))
	}

	return r.ok(t)
}

function proxyError(ce: Error, fe: Error): [number, ErrorResponse] {
	let code: number | undefined
	let error: string | undefined
	let error_description: string | undefined
	let error_uri: string | undefined

	let cr = errors.as(ce, ClientErrorResponse)
	if (cr) {
		code = cr.response.status
		error = cr.error
		error_description = cr.error_description
		error_uri = cr.error_uri
	} else {
		code = 500
		error = "server_error"
		error_description = errors.format(fe)
	}

	let er: ErrorResponse = {
		error,
	}

	if (error_description) {
		er.error_description = error_description
	}

	if (error_uri) {
		er.error_uri = error_uri
	}

	return [code, er]
}
