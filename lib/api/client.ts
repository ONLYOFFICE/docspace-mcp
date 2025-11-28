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
 * @mergeModuleWith api
 */

import * as z from "zod"
import type {Result} from "../util/result.ts"
import {error, ok, safeAsync, safeNew, safeSync} from "../util/result.ts"
import {AuthService} from "./auth-service.ts"
import {FilesService} from "./files-service.ts"
import {PeopleService} from "./people-service.ts"
import {
	ErrorApiResponseSchema,
	SuccessApiResponseSchema,
	UploadChunkErrorResponseSchema,
	UploadChunkSuccessResponseSchema,
	UploadSessionObjectSchema,
} from "./schemas.ts"

const headerAuth = "Authorization"
const headerApiKey = "Authorization"
const headerAuthToken = "Authorization"
const headerBasicAuth = "Authorization"
const schemaApiKey = "Bearer"
const schemaBasicAuth = "Basic"
const schemaBearerAuth = "Bearer"
const cookieAuthToken = "asc_auth_key"

export interface ClientConfig {
	userAgent: string
	baseUrl: string
	fetch: typeof globalThis.fetch
}

export class Client {
	userAgent: string
	baseUrl: string
	baseFetch: typeof globalThis.fetch

	auth: AuthService
	files: FilesService
	people: PeopleService

	constructor(config: ClientConfig) {
		this.userAgent = config.userAgent
		this.baseUrl = config.baseUrl
		this.baseFetch = config.fetch

		this.auth = new AuthService(this)
		this.files = new FilesService(this)
		this.people = new PeopleService(this)
	}

	withAuth(h: string): Client {
		let c = this.copy()

		let f = c.baseFetch

		c.baseFetch = async function baseFetch(input, init) {
			if (!(input instanceof Request)) {
				throw new Error("Unsupported input type.")
			}

			input = input.clone()

			let err = safeSync(input.headers.set.bind(input.headers), headerAuth, h)
			if (err.err) {
				throw new Error("Setting authorization header.", {cause: err.err})
			}

			return await f(input, init)
		}

		return c
	}

	withApiKey(k: string): Client {
		let c = this.copy()

		let f = c.baseFetch

		c.baseFetch = async function baseFetch(input, init) {
			if (!(input instanceof Request)) {
				throw new Error("Unsupported input type.")
			}

			input = input.clone()

			let err = injectAuthKey(input, k)
			if (err) {
				throw new Error("Injecting authentication key.", {cause: err})
			}

			return await f(input, init)
		}

		return c
	}

	withAuthToken(t: string): Client {
		let c = this.copy()

		let f = c.baseFetch

		c.baseFetch = async function baseFetch(input, init) {
			if (!(input instanceof Request)) {
				throw new Error("Unsupported input type.")
			}

			input = input.clone()

			let err = injectAuthToken(input, t)
			if (err) {
				throw new Error("Injecting authentication token.", {cause: err})
			}

			return await f(input, init)
		}

		return c
	}

	withBasicAuth(u: string, p: string): Client {
		let c = this.copy()

		let f = c.baseFetch

		c.baseFetch = async function baseFetch(input, init) {
			if (!(input instanceof Request)) {
				throw new Error("Unsupported input type.")
			}

			input = input.clone()

			let err = injectBasicAuth(input, u, p)
			if (err) {
				throw new Error("Injecting basic authentication.", {cause: err})
			}

			return await f(input, init)
		}

		return c
	}

	withBearerAuth(t: string): Client {
		let c = this.copy()

		let f = c.baseFetch

		c.baseFetch = async function baseFetch(input, init) {
			if (!(input instanceof Request)) {
				throw new Error("Unsupported input type.")
			}

			input = input.clone()

			let err = injectBearerAuth(input, t)
			if (err) {
				throw new Error("Injecting bearer authentication.", {cause: err})
			}

			return await f(input, init)
		}

		return c
	}

	copy(): Client {
		let config: ClientConfig = {
			userAgent: this.userAgent,
			baseUrl: this.baseUrl,
			fetch: this.baseFetch,
		}
		return new Client(config)
	}

	createUrl(path: string, query?: object): Result<string, Error> {
		if (!this.baseUrl.endsWith("/")) {
			return error(new Error(`Base URL must end with a trailing slash, but ${this.baseUrl} does not.`))
		}

		let u = safeNew(URL, path, this.baseUrl)
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		if (query) {
			let q = new URLSearchParams()

			for (let [k, v] of Object.entries(query)) {
				if (v === undefined) {
					continue
				}

				if (Array.isArray(v)) {
					for (let e of v) {
						q.append(k, e.toString())
					}
					continue
				}

				q.append(k, v.toString())
			}

			let s = q.toString()
			if (s) {
				u.v.search = s
			}
		}

		return ok(u.v.toString())
	}

	createRequest(signal: AbortSignal, method: string, url: string, body?: unknown): Result<Request, Error> {
		let c: RequestInit = {
			method,
			signal,
		}

		if (body !== undefined) {
			let b = safeSync(JSON.stringify, body)
			if (b.err) {
				return error(new Error("Stringifying body.", {cause: b.err}))
			}

			c.body = b.v
		}

		let r = safeNew(Request, url, c)
		if (r.err) {
			return error(new Error("Creating request.", {cause: r.err}))
		}

		let h = safeSync(r.v.headers.set.bind(r.v.headers), "Accept", "application/json")
		if (h.err) {
			return error(new Error("Setting header.", {cause: h.err}))
		}

		if (body !== undefined) {
			let h = safeSync(r.v.headers.set.bind(r.v.headers), "Content-Type", "application/json")
			if (h.err) {
				return error(new Error("Setting header.", {cause: h.err}))
			}
		}

		if (this.userAgent) {
			let h = safeSync(r.v.headers.set.bind(r.v.headers), "User-Agent", this.userAgent)
			if (h.err) {
				return error(new Error("Setting header.", {cause: h.err}))
			}
		}

		return ok(r.v)
	}

	createFormRequest(signal: AbortSignal, url: string, body: FormData): Result<Request, Error> {
		let c: RequestInit = {
			body,
			method: "POST",
			signal,
		}

		let r = safeNew(Request, url, c)
		if (r.err) {
			return error(new Error("Creating request.", {cause: r.err}))
		}

		let h = safeSync(r.v.headers.set.bind(r.v.headers), "Accept", "application/json")
		if (h.err) {
			return error(new Error("Setting header.", {cause: h.err}))
		}

		if (this.userAgent) {
			let h = safeSync(r.v.headers.set.bind(r.v.headers), "User-Agent", this.userAgent)
			if (h.err) {
				return error(new Error("Setting header.", {cause: h.err}))
			}
		}

		return ok(r.v)
	}

	async fetch(req: Request): Promise<Result<[unknown, Response], Error>> {
		let f = await this.bareFetch(req)
		if (f.err) {
			return error(new Error("Making bare fetch.", {cause: f.err}))
		}

		let p = await parseSharedResponse(req, f.v)
		if (p.err) {
			return error(new Error("Parsing response.", {cause: p.err}))
		}

		return ok(p.v)
	}

	async bareFetch(req: Request): Promise<Result<globalThis.Response, Error>> {
		let f = await safeAsync(this.baseFetch, req.clone())
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let c = await checkSharedResponse(req, f.v)
		if (c) {
			return error(new Error("Checking response.", {cause: c}))
		}

		return ok(f.v)
	}
}

function injectAuthKey(input: Request, k: string): Error | undefined {
	let h = safeSync(input.headers.set.bind(input.headers), headerApiKey, `${schemaApiKey} ${k}`)
	if (h.err) {
		return new Error("Setting header.", {cause: h.err})
	}
}

function injectAuthToken(input: Request, t: string): Error | undefined {
	let h = safeSync(input.headers.set.bind(input.headers), headerAuthToken, t)
	if (h.err) {
		return new Error("Setting header.", {cause: h.err})
	}

	let p = `${cookieAuthToken}=${t}`

	let c = input.headers.get("Cookie")

	if (c === null) {
		c = p
	} else {
		c = `${c}; ${p}`
	}

	h = safeSync(input.headers.set.bind(input.headers), "Cookie", c)
	if (h.err) {
		return new Error("Setting header.", {cause: h.err})
	}
}

function injectBasicAuth(input: Request, u: string, p: string): Error | undefined {
	let v = Buffer.from(`${u}:${p}`, "utf8").toString("base64")

	let h = safeSync(input.headers.set.bind(input.headers), headerBasicAuth, `${schemaBasicAuth} ${v}`)
	if (h.err) {
		return new Error("Setting header.", {cause: h.err})
	}
}

function injectBearerAuth(input: Request, t: string): Error | undefined {
	let h = safeSync(input.headers.set.bind(input.headers), headerAuthToken, `${schemaBearerAuth} ${t}`)
	if (h.err) {
		return new Error("Setting header.", {cause: h.err})
	}
}

export class Response {
	request: Request
	response: globalThis.Response

	constructor(request: Request, response: globalThis.Response) {
		this.request = request
		this.response = response
	}
}

// eslint-disable-next-line unicorn/custom-error-definition
export class ErrorResponse extends Error {
	response: Response

	constructor(response: Response, message: string) {
		super(message)
		this.name = "ErrorResponse"
		this.response = response
	}
}

const SuccessResponseSchema = z.
	union([
		SuccessApiResponseSchema,
		UploadChunkSuccessResponseSchema,
	]).
	transform((o) => {
		let t: {
			data: unknown
		} = {
			data: undefined,
		}

		switch (true) {
		case "response" in o:
			let u = UploadSessionObjectSchema.safeParse(o.response)
			if (u.success) {
				t.data = u.data.data
			} else {
				t.data = o.response
			}
			break

		case "data" in o:
			t.data = o.data
			break

		// no default
		}

		return t
	})

const ErrorResponseSchema = z.
	union([
		ErrorApiResponseSchema,
		UploadChunkErrorResponseSchema,
	]).
	transform((o) => {
		let t: {
			message: string
		} = {
			message: "",
		}

		switch (true) {
		case "error" in o:
			t.message = o.error.message
			break

		case "message" in o:
			t.message = o.message
			break

		// no default
		}

		return t
	})

export async function checkSharedResponse(req: Request, res: globalThis.Response): Promise<Error | undefined> {
	// DocSpace does not always respect HTTP status codes. Even when it returns
	// HTTP 2xx, it may still include an error in the response body. Therefore,
	// try to first parse the response body for errors before checking the status
	// codes.

	let err = await (async(): Promise<Error> => {
		let c = safeSync(res.clone.bind(res))
		if (c.err) {
			return new Error("Cloning response.", {cause: c.err})
		}

		let b = await safeAsync(c.v.json.bind(c.v))
		if (b.err) {
			return new Error("Parsing response body.", {cause: b.err})
		}

		let s = ErrorResponseSchema.safeParse(b.v)
		if (!s.success) {
			return new Error("Parsing error response.", {cause: s.error})
		}

		let r = new Response(req, res)
		let m = `${req.method} ${req.url}: ${res.status} ${s.data.message}`
		let e = new ErrorResponse(r, m)

		return e
	})()

	if (err instanceof ErrorResponse) {
		return err
	}

	if (res.status >= 200 && res.status <= 299) {
		return
	}

	let r = new Response(req, res)
	let m = `${req.method} ${req.url}: ${res.status} ${res.statusText}`
	let e = new ErrorResponse(r, m)

	return e
}

export async function parseSharedResponse(req: Request, res: globalThis.Response): Promise<Result<[unknown, Response], Error>> {
	let c = safeSync(res.clone.bind(res))
	if (c.err) {
		return error(new Error("Cloning response.", {cause: c.err}))
	}

	let b = await safeAsync(c.v.json.bind(c.v))
	if (b.err) {
		return error(new Error("Parsing response body.", {cause: b.err}))
	}

	let s = SuccessResponseSchema.safeParse(b.v)
	if (!s.success) {
		return error(new Error("Parsing success response.", {cause: s.error}))
	}

	let r = new Response(req, res)
	return ok([s.data.data, r])
}
