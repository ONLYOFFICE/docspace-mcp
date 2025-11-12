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

import type express from "express"
import * as errors from "../util/errors.ts"
import * as r from "../util/result.ts"
import type {AuthTokenPayload} from "./auth.ts"
import {InvalidAuthTokenError} from "./auth.ts"
import type {ClientResponse} from "./client.ts"
import {proxyError} from "./internal.ts"
import type {ErrorResponse, IntrospectRequest, IntrospectResponse} from "./shared.ts"

declare module "express-serve-static-core" {
	interface Request {
		oauth?: Oauth
	}
}

export const handlerRequestHeaders: string[] = [
	"Authorization",
]

export const handlerResponseHeaders: string[] = [
	"Content-Type",
	"WWW-Authenticate",
]

export type Oauth = {
	aud: string
	token: string
}

export type HandlerConfig = {
	baseUrl: string
	client: HandlerClient
	authTokens: HandlerAuthTokens
}

export type HandlerClient = {
	introspect(s: AbortSignal | undefined, o: IntrospectRequest): Promise<r.Result<[IntrospectResponse, ClientResponse], Error>>
}

export type HandlerAuthTokens = {
	verify(t: string): r.Result<[string, AuthTokenPayload], Error>
	encode(t: string): r.Result<[string, AuthTokenPayload], Error>
}

/**
 * {@link https://www.rfc-editor.org/rfc/rfc6750.html#section-3 | RFC 6750 Reference}
 */
export function handler(config: HandlerConfig): r.Result<express.Handler, Error> {
	let u = r.safeNew(URL, "/.well-known/oauth-protected-resource", config.baseUrl)
	if (u.err) {
		return r.error(new Error("Creating resource metadata URL", {cause: u.err}))
	}

	let www = (e: ErrorResponse): string => {
		let s = `Bearer error="${e.error}", `

		if (e.error_description) {
			s += `error_description=${JSON.stringify(e.error_description)}, `
		}

		if (e.error_uri) {
			s += `error_uri="${e.error_uri}", `
		}

		s += `resource_metadata="${u.v}"`

		return s
	}

	let end = (res: express.Response, code: number, er: ErrorResponse): void => {
		if (code === 401 || code === 403) {
			res.set("WWW-Authenticate", www(er))
		}
		res.status(code)
		res.json(er)
	}

	let h: express.Handler = async(req, res, next) => {
		let ih = parseBearer(req)
		if (ih.err) {
			let err = new Error("Parsing header", {cause: ih.err})
			let er: ErrorResponse = {
				error: "invalid_request",
				error_description: errors.format(err),
			}
			end(res, 401, er)
			return
		}

		let tu = config.authTokens.verify(ih.v)
		if (tu.err) {
			let err = new Error("Verifying token", {cause: tu.err})

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

			end(res, code, er)
			return
		}

		let [tt, tp] = tu.v

		if (!tp.pld.aud) {
			let err = new Error("No audience")
			let er: ErrorResponse = {
				error: "server_error",
				error_description: errors.format(err),
			}
			end(res, 500, er)
			return
		}

		if (!(typeof tp.pld.aud === "string")) {
			let err = new Error("Invalid audience")
			let er: ErrorResponse = {
				error: "server_error",
				error_description: errors.format(err),
			}
			end(res, 500, er)
			return
		}

		let io: IntrospectRequest = {
			token: tt,
		}

		let ci = await config.client.introspect(req.signal, io)
		if (ci.err) {
			let err = new Error("Introspecting token", {cause: ci.err})
			let [code, er] = proxyError(ci.err, err)
			end(res, code, er)
			return
		}

		let [id] = ci.v

		if (!id.active) {
			let err = new Error("Inactive token")
			let er: ErrorResponse = {
				error: "invalid_token",
				error_description: errors.format(err),
			}
			end(res, 401, er)
			return
		}

		if (id.exp && id.exp < Math.floor(Date.now() / 1000)) {
			let err = new Error("Expired token")
			let er: ErrorResponse = {
				error: "invalid_token",
				error_description: errors.format(err),
			}
			end(res, 401, er)
			return
		}

		req.oauth = {
			aud: tp.pld.aud,
			token: tt,
		}

		next()
	}

	return r.ok(h)
}

function parseBearer(req: express.Request): r.Result<string, Error> {
	let h = req.headers.authorization

	if (!h) {
		return r.error(new Error("No header"))
	}

	let i = h.indexOf(" ")

	if (i === -1) {
		return r.error(new Error("Malformed header"))
	}

	let s = h.slice(0, i)

	if (!s) {
		return r.error(new Error("No scheme"))
	}

	if (s.toLowerCase() !== "bearer") {
		return r.error(new Error("Invalid scheme"))
	}

	let t = h.slice(i + 1)

	if (!t) {
		return r.error(new Error("No token"))
	}

	return r.ok(t)
}
