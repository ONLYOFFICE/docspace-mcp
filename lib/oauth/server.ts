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

import express from "express"
import jwt from "jsonwebtoken"
import * as errors from "../util/errors.ts"
import * as utilExpress from "../util/express.ts"
import * as r from "../util/result.ts"
import type {AuthTokenPayload} from "./auth.ts"
import {InvalidAuthTokenError} from "./auth.ts"
import type {ClientResponse, ClientRevokeRequest, ClientTokenRequest} from "./client.ts"
import {proxyError} from "./internal.ts"
import type {
	AuthorizeRequest,
	AuthorizeResponse,
	ClientPassword,
	ErrorResponse,
	IntrospectRequest,
	IntrospectResponse,
	RegisterResponse,
	ResourceMetadataResponse,
	ServerMetadataResponse,
	TokenResponse,
} from "./shared.ts"
import {
	AuthorizeRequestSchema,
	AuthorizeResponseSchema,
	ClientCredentialsSchema,
	ClientPasswordSchema,
	IntrospectRequestSchema,
	PartialClientCredentialsSchema,
	RevokeRequestSchema,
	TokenRequestSchema,
} from "./shared.ts"
import type {State} from "./state.ts"
import {InvalidStateTokenError} from "./state.ts"

export type ServerConfig = {
	baseUrl: string
	clientId: string
	clientSecret: string
	scopes: string[]
	corsOrigin: string[]
	corsMaxAge: number
	serverMetadataRateLimitCapacity: number
	serverMetadataRateLimitWindow: number
	resourceMetadataRateLimitCapacity: number
	resourceMetadataRateLimitWindow: number
	authorizeRateLimitCapacity: number
	authorizeRateLimitWindow: number
	callbackRateLimitCapacity: number
	callbackRateLimitWindow: number
	introspectRateLimitCapacity: number
	introspectRateLimitWindow: number
	registerRateLimitCapacity: number
	registerRateLimitWindow: number
	revokeRateLimitCapacity: number
	revokeRateLimitWindow: number
	tokenRateLimitCapacity: number
	tokenRateLimitWindow: number
	client: ServerClient
	authTokens: ServerAuthTokens
	stateTokens: ServerStateTokens
}

export type ServerClient = {
	authorize(o: AuthorizeRequest): r.Result<URL, Error>
	introspect(s: AbortSignal | undefined, o: IntrospectRequest): Promise<r.Result<[IntrospectResponse, ClientResponse], Error>>
	revoke(s: AbortSignal | undefined, o: ClientRevokeRequest): Promise<r.Result<ClientResponse, Error>>
	token(s: AbortSignal | undefined, o: ClientTokenRequest): Promise<r.Result<[TokenResponse, ClientResponse], Error>>
}

export type ServerAuthTokens = {
	verify(t: string): r.Result<[string, AuthTokenPayload], Error>
	encode(t: string): r.Result<[string, AuthTokenPayload], Error>
}

export type ServerStateTokens = {
	verify(t: string): r.Result<State, Error>
	encode(s: State): r.Result<string, Error>
}

export class Server {
	private clientId: string
	private clientSecret: string
	private corsOrigin: string[]
	private corsMaxAge: number
	private serverMetadataRateLimitCapacity: number
	private serverMetadataRateLimitWindow: number
	private resourceMetadataRateLimitCapacity: number
	private resourceMetadataRateLimitWindow: number
	private authorizeRateLimitCapacity: number
	private authorizeRateLimitWindow: number
	private callbackRateLimitCapacity: number
	private callbackRateLimitWindow: number
	private introspectRateLimitCapacity: number
	private introspectRateLimitWindow: number
	private registerRateLimitCapacity: number
	private registerRateLimitWindow: number
	private revokeRateLimitCapacity: number
	private revokeRateLimitWindow: number
	private tokenRateLimitCapacity: number
	private tokenRateLimitWindow: number

	private client: ServerClient
	private authTokens: ServerAuthTokens
	private stateTokens: ServerStateTokens

	private issuer: string
	private scope: string
	private authorizeUrl: string
	private callbackUrl: string
	private introspectUrl: string
	private registerUrl: string
	private revokeUrl: string
	private tokenUrl: string

	constructor(config: ServerConfig) {
		this.clientId = config.clientId
		this.clientSecret = config.clientSecret
		this.corsOrigin = config.corsOrigin
		this.corsMaxAge = config.corsMaxAge
		this.serverMetadataRateLimitCapacity = config.serverMetadataRateLimitCapacity
		this.serverMetadataRateLimitWindow = config.serverMetadataRateLimitWindow
		this.resourceMetadataRateLimitCapacity = config.resourceMetadataRateLimitCapacity
		this.resourceMetadataRateLimitWindow = config.resourceMetadataRateLimitWindow
		this.authorizeRateLimitCapacity = config.authorizeRateLimitCapacity
		this.authorizeRateLimitWindow = config.authorizeRateLimitWindow
		this.callbackRateLimitCapacity = config.callbackRateLimitCapacity
		this.callbackRateLimitWindow = config.callbackRateLimitWindow
		this.introspectRateLimitCapacity = config.introspectRateLimitCapacity
		this.introspectRateLimitWindow = config.introspectRateLimitWindow
		this.registerRateLimitCapacity = config.registerRateLimitCapacity
		this.registerRateLimitWindow = config.registerRateLimitWindow
		this.revokeRateLimitCapacity = config.revokeRateLimitCapacity
		this.revokeRateLimitWindow = config.revokeRateLimitWindow
		this.tokenRateLimitCapacity = config.tokenRateLimitCapacity
		this.tokenRateLimitWindow = config.tokenRateLimitWindow

		this.client = config.client
		this.authTokens = config.authTokens
		this.stateTokens = config.stateTokens

		let pb = r.safeNew(URL, "/", config.baseUrl)
		if (pb.err) {
			throw new Error("Creating base URL", {cause: pb.v})
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

		if (pb.v.href.endsWith("/")) {
			this.issuer = pb.v.href.slice(0, -1)
		} else {
			this.issuer = pb.v.href
		}

		this.scope = config.scopes.join(" ")

		this.authorizeUrl = pa.v.href
		this.callbackUrl = pc.v.href
		this.introspectUrl = pi.v.href
		this.registerUrl = pg.v.href
		this.revokeUrl = pv.v.href
		this.tokenUrl = pt.v.href
	}

	router(): express.Router {
		// todo: add recovery middleware

		let ao: AuthOptions = {
			clientId: this.clientId,
			clientSecret: this.clientSecret,
		}

		let a = auth(ao)

		let corsMetadata = (r: express.Router): void => {
			if (this.corsOrigin.length !== 0) {
				let co: utilExpress.CorsOptions = {
					origin: this.corsOrigin,
					maxAge: this.corsMaxAge,
					methods: ["GET"],
					allowedHeaders: [],
					exposedHeaders: [],
				}

				if (
					this.serverMetadataRateLimitCapacity &&
					this.serverMetadataRateLimitWindow ||
					this.resourceMetadataRateLimitCapacity &&
					this.resourceMetadataRateLimitWindow
				) {
					co.exposedHeaders.push(...utilExpress.rateLimitHeaders)
				}

				r.use(utilExpress.cors(co))
			}
		}

		let corsOauth = (r: express.Router): void => {
			if (this.corsOrigin.length !== 0) {
				let co: utilExpress.CorsOptions = {
					origin: this.corsOrigin,
					maxAge: this.corsMaxAge,
					methods: ["GET", "POST"],
					allowedHeaders: [
						"Authorization",
						"Content-Type",
					],
					exposedHeaders: [
						"WWW-Authenticate",
					],
				}

				if (
					this.authorizeRateLimitCapacity &&
					this.authorizeRateLimitWindow ||
					this.callbackRateLimitCapacity &&
					this.callbackRateLimitWindow ||
					this.introspectRateLimitCapacity &&
					this.introspectRateLimitWindow ||
					this.clientId &&
					this.registerRateLimitCapacity &&
					this.registerRateLimitWindow ||
					this.revokeRateLimitCapacity &&
					this.revokeRateLimitWindow ||
					this.tokenRateLimitCapacity &&
					this.tokenRateLimitWindow
				) {
					co.exposedHeaders.push(...utilExpress.rateLimitHeaders)
				}

				r.use(utilExpress.cors(co))
			}
		}

		let r = express.Router()

		r.use("/.well-known/oauth-authorization-server", (() => {
			let r = express.Router()

			corsMetadata(r)

			let go: GuardOptions = {
				methods: ["GET"],
				types: [],
				capacity: this.serverMetadataRateLimitCapacity,
				window: this.serverMetadataRateLimitWindow,
			}

			guard(r, go)

			r.use(this.handleServerMetadata.bind(this))

			return r
		})())

		r.use("/.well-known/oauth-protected-resource", (() => {
			let r = express.Router()

			corsMetadata(r)

			let go: GuardOptions = {
				methods: ["GET"],
				types: [],
				capacity: this.resourceMetadataRateLimitCapacity,
				window: this.resourceMetadataRateLimitWindow,
			}

			guard(r, go)

			r.use(this.handleResourceMetadata.bind(this))

			return r
		})())

		r.use("/oauth", (() => {
			let r = express.Router()

			r.use(utilExpress.signal())
			r.use(express.json())
			r.use(express.urlencoded({extended: true}))

			corsOauth(r)

			r.use("/authorize", (() => {
				let r = express.Router()

				let go: GuardOptions = {
					methods: ["GET"],
					types: [],
					capacity: this.authorizeRateLimitCapacity,
					window: this.authorizeRateLimitWindow,
				}

				guard(r, go)

				r.use(this.handleAuthorize.bind(this))

				return r
			})())

			r.use("/callback", (() => {
				let r = express.Router()

				let go: GuardOptions = {
					methods: ["GET"],
					types: [],
					capacity: this.callbackRateLimitCapacity,
					window: this.callbackRateLimitWindow,
				}

				guard(r, go)

				r.use(this.handleCallback.bind(this))

				return r
			})())

			r.use("/introspect", (() => {
				let r = express.Router()

				r.use(a)

				let go: GuardOptions = {
					methods: ["POST"],
					types: ["application/x-www-form-urlencoded"],
					capacity: this.introspectRateLimitCapacity,
					window: this.introspectRateLimitWindow,
				}

				guard(r, go)

				r.use(this.handleIntrospect.bind(this))

				return r
			})())

			if (this.clientId) {
				r.use("/register", (() => {
					let r = express.Router()

					let go: GuardOptions = {
						methods: ["POST"],
						types: ["application/json"],
						capacity: this.registerRateLimitCapacity,
						window: this.registerRateLimitWindow,
					}

					guard(r, go)

					r.use(this.handleRegister.bind(this))

					return r
				})())
			}

			r.use("/revoke", (() => {
				let r = express.Router()

				r.use(a)

				let go: GuardOptions = {
					methods: ["POST"],
					types: ["application/x-www-form-urlencoded"],
					capacity: this.revokeRateLimitCapacity,
					window: this.revokeRateLimitWindow,
				}

				guard(r, go)

				r.use(this.handleRevoke.bind(this))

				return r
			})())

			r.use("/token", (() => {
				let r = express.Router()

				r.use(a)

				let go: GuardOptions = {
					methods: ["POST"],
					types: ["application/x-www-form-urlencoded"],
					capacity: this.tokenRateLimitCapacity,
					window: this.tokenRateLimitWindow,
				}

				guard(r, go)

				r.use(this.handleToken.bind(this))

				return r
			})())

			return r
		})())

		return r
	}

	/**
	 * {@link https://www.rfc-editor.org/rfc/rfc8414#section-3 | RFC 8414 Reference}
	 */
	private handleServerMetadata(_: express.Request, res: express.Response): void {
		let re: string | undefined
		let am: string[] | undefined

		if (this.clientId) {
			re = this.registerUrl
			am = ["none"]
		} else {
			re = ""
			am = []
		}

		let ob: ServerMetadataResponse = {
			issuer: this.issuer,
			authorization_endpoint: this.authorizeUrl,
			token_endpoint: this.tokenUrl,
			registration_endpoint: re,
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
				...am,
			],
			revocation_endpoint: this.revokeUrl,
			revocation_endpoint_auth_methods_supported: [
				"client_secret_basic",
				"client_secret_post",
				...am,
			],
			introspection_endpoint: this.introspectUrl,
			introspection_endpoint_auth_methods_supported: [
				"client_secret_basic",
				"client_secret_post",
				...am,
			],
			code_challenge_methods_supported: [
				"S256",
			],
		}

		if (ob.registration_endpoint === "") {
			delete ob.registration_endpoint
		}

		res.status(200)
		res.json(ob)
	}

	/**
	 * {@link https://www.rfc-editor.org/rfc/rfc9728#name-obtaining-protected-resourc | RFC 9728 Reference}
	 */
	private handleResourceMetadata(_: express.Request, res: express.Response): void {
		let ob: ResourceMetadataResponse = {
			resource: this.issuer,
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
			let [code, er] = proxyError(ca.err, err)
			res.status(code)
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

		let sd = this.stateTokens.verify(iq.data.state)
		if (sd.err) {
			let err = new Error("Verifying token", {cause: sd.err})

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
		if (!req[authKey]) {
			let err = new Error("No auth")
			let er: ErrorResponse = {
				error: "server_error",
				error_description: errors.format(err),
			}
			res.status(500)
			res.json(er)
			return
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

		let tu = this.authTokens.verify(ib.data.token)
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

			let err = new Error("Verifying token", {cause: tu.err})

			let code: number | undefined
			let error: string | undefined

			if (errors.as(tu.err, InvalidAuthTokenError)) {
				code = 400
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
			let [code, er] = proxyError(ci.err, err)
			res.status(code)
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
		}
		res.status(201)
		res.json(ob)
	}

	/**
	 * {@link https://www.rfc-editor.org/rfc/rfc7009#section-2 | RFC 7009 Reference}
	 */
	private async handleRevoke(req: express.Request, res: express.Response): Promise<void> {
		if (!req[authKey]) {
			let err = new Error("No auth")
			let er: ErrorResponse = {
				error: "server_error",
				error_description: errors.format(err),
			}
			res.status(500)
			res.json(er)
			return
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

		let ro: ClientRevokeRequest = {
			token: ib.data.token,
			client_id: req[authKey].clientId,
			client_secret: req[authKey].clientSecret,
		}

		if (ib.data.token_type_hint) {
			ro.token_type_hint = ib.data.token_type_hint
		}

		let cr = await this.client.revoke(req.signal, ro)
		if (cr.err) {
			let err = new Error("Revoking token", {cause: cr.err})
			let [code, er] = proxyError(cr.err, err)
			res.status(code)
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
		if (!req[authKey]) {
			let err = new Error("No auth")
			let er: ErrorResponse = {
				error: "server_error",
				error_description: errors.format(err),
			}
			res.status(500)
			res.json(er)
			return
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

		let to: ClientTokenRequest | undefined

		switch (ib.data.grant_type) {
		case "authorization_code":
			to = {
				grant_type: ib.data.grant_type,
				code: ib.data.code,
				redirect_uri: this.callbackUrl,
				client_id: req[authKey].clientId,
				client_secret: req[authKey].clientSecret,
			}
			break

		case "refresh_token":
			to = {
				grant_type: ib.data.grant_type,
				refresh_token: ib.data.refresh_token,
				client_id: req[authKey].clientId,
				client_secret: req[authKey].clientSecret,
			}
			break
		}

		let ct = await this.client.token(req.signal, to)
		if (ct.err) {
			let err = new Error("Requesting token", {cause: ct.err})
			let [code, er] = proxyError(ct.err, err)
			res.status(code)
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

type GuardOptions = {
	methods: string[]
	types: string[]
	capacity: number
	window: number
}

function guard(r: express.Router, o: GuardOptions): void {
	if (o.methods.length !== 0) {
		let er: ErrorResponse = {
			error: "invalid_request",
			error_description: "Method Not Allowed",
		}

		r.use(utilExpress.allowedMethods(o.methods, (_, res) => {
			res.json(er)
		}))
	}

	if (o.types.length !== 0) {
		let er: ErrorResponse = {
			error: "invalid_request",
			error_description: "Unsupported Media Type",
		}

		r.use(utilExpress.supportedMediaTypes(o.types, (_, res) => {
			res.json(er)
		}))
	}

	if (o.capacity && o.window) {
		let er: ErrorResponse = {
			error: "too_many_requests",
			error_description: "Too Many Requests",
		}

		let ro: utilExpress.RateLimitOptions = {
			capacity: o.capacity,
			window: o.window,
		}

		r.use(utilExpress.rateLimit(ro, (_, res) => {
			res.json(er)
		}))
	}
}

declare module "express-serve-static-core" {
	interface Request {
		[authKey]?: Auth
	}
}

const authKey = Symbol("auth")

type Auth = {
	clientId: string
	clientSecret: string
}

type AuthOptions = {
	clientId: string
	clientSecret: string
}

function auth(o: AuthOptions): express.Handler {
	return (req, res, next) => {
		if (req.headers.authorization) {
			let h = parseBasic(req.headers.authorization)
			if (h.err) {
				let err = new Error("Parsing header", {cause: h.err})
				let er: ErrorResponse = {
					error: "invalid_client",
					error_description: errors.format(err),
				}
				res.set('WWW-Authenticate: Basic realm="OAuth"')
				res.status(401)
				res.json(er)
				return
			}

			let b = PartialClientCredentialsSchema.safeParse(req.body)
			if (!b.success) {
				let err = new Error("Parsing body", {cause: b.error})
				let er: ErrorResponse = {
					error: "invalid_request",
					error_description: errors.format(err),
				}
				res.status(400)
				res.json(er)
				return
			}

			if (b.data.client_id || b.data.client_secret) {
				let err = new Error("Multiple authentication methods")
				let er: ErrorResponse = {
					error: "invalid_request",
					error_description: errors.format(err),
				}
				res.status(400)
				res.json(er)
				return
			}

			req[authKey] = {
				clientId: h.v.client_id,
				clientSecret: h.v.client_secret,
			}
			next()
			return
		}

		if (o.clientId) {
			let b = ClientCredentialsSchema.safeParse(req.body)
			if (!b.success) {
				let err = new Error("Parsing body", {cause: b.error})
				let er: ErrorResponse = {
					error: "invalid_request",
					error_description: errors.format(err),
				}
				res.status(400)
				res.json(er)
				return
			}

			if (!b.data.client_secret) {
				if (b.data.client_id !== o.clientId) {
					let err = new Error("Client ID mismatch")
					let er: ErrorResponse = {
						error: "invalid_client",
						error_description: errors.format(err),
					}
					res.set('WWW-Authenticate: Basic realm="OAuth"')
					res.status(401)
					res.json(er)
					return
				}

				req[authKey] = {
					clientId: o.clientId,
					clientSecret: o.clientSecret,
				}
				next()
				return
			}

			req[authKey] = {
				clientId: b.data.client_id,
				clientSecret: b.data.client_secret,
			}
			next()
			return
		}

		let b = ClientPasswordSchema.safeParse(req.body)
		if (!b.success) {
			let err = new Error("Parsing body", {cause: b.error})
			let er: ErrorResponse = {
				error: "invalid_request",
				error_description: errors.format(err),
			}
			res.status(400)
			res.json(er)
			return
		}

		req[authKey] = {
			clientId: b.data.client_id,
			clientSecret: b.data.client_secret,
		}
		next()
	}
}

function parseBasic(h: string): r.Result<ClientPassword, Error> {
	let i = h.indexOf(" ")

	if (i === -1) {
		return r.error(new Error("Malformed header"))
	}

	let v = h.slice(0, i)

	if (!v) {
		return r.error(new Error("No scheme"))
	}

	if (v.toLowerCase() !== "basic") {
		return r.error(new Error("Invalid scheme"))
	}

	v = h.slice(i + 1)

	if (!v) {
		return r.error(new Error("No password"))
	}

	v = Buffer.from(v, "base64").toString()

	i = v.indexOf(":")

	if (i === -1) {
		return r.error(new Error("Malformed password"))
	}

	let x = h.slice(0, i)

	if (!x) {
		return r.error(new Error("No client_id"))
	}

	let y = h.slice(i + 1)

	if (!y) {
		return r.error(new Error("No client_secret"))
	}

	let c: ClientPassword = {
		client_id: x,
		client_secret: y,
	}

	return r.ok(c)
}
