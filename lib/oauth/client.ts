/**
 * @module
 * @mergeModuleWith oauth
 */

import contentType from "content-type"
import * as z from "zod"
import * as errors from "../util/errors.ts"
import * as r from "../util/result.ts"
import type {
	AuthorizeRequest,
	ClientPassword,
	IntrospectRequest,
	IntrospectResponse,
	RevokeRequest,
	TokenRequest,
	TokenResponse,
} from "./shared.ts"
import {ErrorResponseSchema, IntrospectResponseSchema, TokenResponseSchema} from "./shared.ts"

export type ClientRevokeRequest = RevokeRequest & ClientPassword

export type ClientTokenRequest = TokenRequest & ClientPassword

export const ClientCustomErrorResponseSchema = z.object({
	reason: z.string(),
})

export type ClientResponseOptions = {
	request: Request
	response: Response
}

export class ClientResponse {
	request: Request
	response: Response

	constructor(o: ClientResponseOptions) {
		this.request = o.request
		this.response = o.response
	}
}

export type ClientResponseErrorOptions = {
	request: Request
	response: Response
	error: string
	error_description: string
	error_uri: string
	message: string
}

export class ClientResponseError extends Error {
	request: Request
	response: Response
	error: string
	error_description: string
	error_uri: string

	constructor(o: ClientResponseErrorOptions) {
		super(o.message)
		this.name = "ClientResponseError"
		this.request = o.request
		this.response = o.response
		this.error = o.error
		this.error_description = o.error_description
		this.error_uri = o.error_uri
	}
}

export type ClientConfig = {
	userAgent: string
	baseUrl: string
	fetch: typeof fetch
}

export class Client {
	private userAgent: string
	private baseUrl: string
	private baseFetch: typeof fetch

	constructor(config: ClientConfig) {
		let b = r.safeNew(URL, config.baseUrl)
		if (b.err) {
			throw new Error("Parsing base URL", {cause: b.err})
		}

		if (!b.v.pathname.endsWith("/")) {
			throw new Error("Base URL does not have trailing slash")
		}

		if (b.v.search) {
			throw new Error("Base URL contains search parameters")
		}

		if (b.v.hash) {
			throw new Error("Base URL contains hash fragment")
		}

		this.userAgent = config.userAgent
		this.baseUrl = b.v.href
		this.baseFetch = config.fetch
	}

	authorize(o: AuthorizeRequest): r.Result<URL, Error> {
		let u = this.createUrl("oauth2/authorize", o)
		if (u.err) {
			return r.error(new Error("Creating URL", {cause: u.err}))
		}
		return r.ok(u.v)
	}

	async introspect(o: IntrospectRequest): Promise<r.Result<[IntrospectResponse, ClientResponse], Error>> {
		let u = this.createUrl("oauth2/introspect")
		if (u.err) {
			return r.error(new Error("Creating URL", {cause: u.err}))
		}

		let req = this.createRequest(u.v, o)
		if (req.err) {
			return r.error(new Error("Creating request", {cause: req.err}))
		}

		let f = await this.fetch(req.v)
		if (f.err) {
			return r.error(new Error("Making request", {cause: f.err}))
		}

		let [v, res] = f.v

		let p = IntrospectResponseSchema.safeParse(v)
		if (!p.success) {
			return r.error(new Error("Parsing response", {cause: p.error}))
		}

		return r.ok([p.data, res])
	}

	async revoke(o: ClientRevokeRequest): Promise<r.Result<ClientResponse, Error>> {
		let u = this.createUrl("oauth2/revoke")
		if (u.err) {
			return r.error(new Error("Creating URL", {cause: u.err}))
		}

		let req = this.createRequest(u.v, o)
		if (req.err) {
			return r.error(new Error("Creating request", {cause: req.err}))
		}

		let f = await this.bareFetch(req.v)
		if (f.err) {
			return r.error(new Error("Making bare request", {cause: f.err}))
		}

		let c: ClientResponseOptions = {
			request: req.v,
			response: f.v,
		}

		let w = new ClientResponse(c)

		return r.ok(w)
	}

	async token(o: ClientTokenRequest): Promise<r.Result<[TokenResponse, ClientResponse], Error>> {
		let u = this.createUrl("oauth2/token")
		if (u.err) {
			return r.error(new Error("Creating URL", {cause: u.err}))
		}

		let req = this.createRequest(u.v, o)
		if (req.err) {
			return r.error(new Error("Creating request", {cause: req.err}))
		}

		let f = await this.fetch(req.v)
		if (f.err) {
			return r.error(new Error("Making request", {cause: f.err}))
		}

		let [v, res] = f.v

		let p = TokenResponseSchema.safeParse(v)
		if (!p.success) {
			return r.error(new Error("Parsing response", {cause: p.error}))
		}

		return r.ok([p.data, res])
	}

	createUrl(p: string, q?: object): r.Result<URL, Error> {
		let u = r.safeNew(URL, p, this.baseUrl)
		if (u.err) {
			return r.error(new Error("Paring path", {cause: u.err}))
		}

		if (q) {
			let p = new URLSearchParams()

			for (let [k, v] of Object.entries(q)) {
				if (v !== undefined) {
					p.append(k, v.toString())
				}
			}

			if (p.size !== 0) {
				u.v.search = p.toString()
			}
		}

		return r.ok(u.v)
	}

	createRequest(u: URL, b: object): r.Result<Request, Error> {
		let p = new URLSearchParams()

		for (let [k, v] of Object.entries(b)) {
			if (Array.isArray(v)) {
				p.append(k, v.join(" "))
			} else if (v !== undefined) {
				p.append(k, v.toString())
			}
		}

		let c: RequestInit = {
			method: "POST",
		}

		if (p.size !== 0) {
			c.body = p
		}

		let req = r.safeNew(Request, u, c)
		if (req.err) {
			return r.error(new Error("Creating request", {cause: req.err}))
		}

		req.v.headers.set("Accept", "application/json")
		req.v.headers.set("Content-Type", "application/x-www-form-urlencoded")

		if (this.userAgent) {
			req.v.headers.set("User-Agent", this.userAgent)
		}

		return r.ok(req.v)
	}

	async fetch(req: Request): Promise<r.Result<[unknown, ClientResponse], Error>> {
		let f = await this.bareFetch(req)
		if (f.err) {
			return r.error(new Error("Making bare request", {cause: f.err}))
		}

		let p = await parseResponse(req, f.v)
		if (p.err) {
			return r.error(new Error("Parsing response.", {cause: p.err}))
		}

		return r.ok(p.v)
	}

	async bareFetch(req: Request): Promise<r.Result<Response, Error>> {
		let f = await r.safeAsync(this.baseFetch, req.clone())
		if (f.err) {
			return r.error(new Error("Making native request", {cause: f.err}))
		}

		let c = await checkResponse(req, f.v)
		if (c.err) {
			return r.error(new Error("Checking response", {cause: c.err}))
		}

		return r.ok(f.v)
	}
}

export async function checkResponse(req: Request, res: Response): Promise<r.Result<void, Error>> {
	if (res.status >= 200 && res.status <= 299) {
		return r.ok()
	}

	let o: ClientResponseErrorOptions = {
		request: req,
		response: res,
		error: "",
		error_description: "",
		error_uri: "",
		message: "",
	}

	await (async() => {
		let h = res.headers.get("Content-Type")
		if (!h) {
			let err = new Error("Content-Type is missing")
			o.error = "server_error"
			o.error_description = errors.format(err)
			return
		}

		let p = r.safeSync(contentType.parse, h)
		if (p.err) {
			let err = new Error("Parsing Content-Type", {cause: p.err})
			o.error = "server_error"
			o.error_description = errors.format(err)
			return
		}

		if (p.v.type !== "application/json") {
			let err = new Error("Content-Type is invalid")
			o.error = "server_error"
			o.error_description = errors.format(err)
			return
		}

		let c = r.safeSync(res.clone.bind(res))
		if (c.err) {
			let err = new Error("Cloning response", {cause: c.err})
			o.error = "server_error"
			o.error_description = errors.format(err)
			return
		}

		let b = await r.safeAsync(c.v.json.bind(c.v))
		if (b.err) {
			let err = new Error("Parsing response", {cause: b.err})
			o.error = "server_error"
			o.error_description = errors.format(err)
			return
		}

		let x = ErrorResponseSchema.safeParse(b.v)
		if (x.success) {
			o.error = x.data.error

			if (x.data.error_description) {
				o.error_description = x.data.error_description
			}

			if (x.data.error_uri) {
				o.error_uri = x.data.error_uri
			}

			return
		}

		let y = ClientCustomErrorResponseSchema.safeParse(b.v)
		if (y.success) {
			o.error = "server_error"
			o.error_description = y.data.reason
			return
		}
	})()

	o.message = `${req.method} ${req.url}: ${res.status} `

	if (o.error) {
		o.message += `${o.error} `
	}

	if (o.error_description) {
		o.message += `${o.error_description} `
	}

	o.message = o.message.slice(0, -1)

	let e = new ClientResponseError(o)

	return r.error(e)
}

export async function parseResponse(req: Request, res: Response): Promise<r.Result<[unknown, ClientResponse], Error>> {
	let c = r.safeSync(res.clone.bind(res))
	if (c.err) {
		return r.error(new Error("Cloning response", {cause: c.err}))
	}

	let b = await r.safeAsync(c.v.json.bind(c.v))
	if (b.err) {
		return r.error(new Error("Parsing body", {cause: b.err}))
	}

	let o: ClientResponseOptions = {
		request: req,
		response: res,
	}

	let w = new ClientResponse(o)

	return r.ok([b.v, w])
}
