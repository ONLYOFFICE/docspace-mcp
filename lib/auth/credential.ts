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
 * @mergeModuleWith auth
 */

/* eslint-disable typescript/consistent-type-definitions */

import type express from "express"
import * as z from "zod"
import * as errors from "../util/errors.ts"
import * as r from "../util/result.ts"
import * as zod from "../util/zod.ts"

export type Credential = {
	baseUrl: string
	apiKey: string
	pat: string
	username: string
	password: string
}

type CredentialQuery = z.infer<Exclude<CredentialParser["querySchema"], undefined>>

type CredentialHeader = z.infer<Exclude<CredentialParser["headerSchema"], undefined>>

export type CredentialParserConfig = {
	queryEnabled: boolean
	headerPrefix: string
}

export class CredentialParser {
	requestHeaders: string[]

	private querySchema
	private headerSchema

	constructor(config: CredentialParserConfig) {
		this.requestHeaders = []

		if (config.queryEnabled) {
			this.querySchema = z.
				object({
					base_url: z.string().optional().transform(zod.envOptionalBaseUrl()),
				}).
				transform((o) => ({
					baseUrl: o.base_url,
				}))
		}

		if (config.headerPrefix) {
			let baseUrl = `${config.headerPrefix}base-url`
			let apiKey = `${config.headerPrefix}api-key`
			let pat = `${config.headerPrefix}auth-token`
			let username = `${config.headerPrefix}username`
			let password = `${config.headerPrefix}password`

			this.requestHeaders.push(
				baseUrl,
				apiKey,
				pat,
				username,
				password,
			)

			this.headerSchema = z.
				object({
					[baseUrl]: z.string().optional().transform(zod.envOptionalBaseUrl()),
					[apiKey]: z.string().trim().optional(),
					[pat]: z.string().trim().optional(),
					[username]: z.string().time().optional(),
					[password]: z.string().time().optional(),
				}).
				transform((o) => ({
					baseUrl: o[baseUrl],
					apiKey: o[apiKey],
					pat: o[pat],
					username: o[username],
					password: o[password],
				}))
		}
	}

	parse(req: express.Request): r.Result<Credential, Error> {
		let q: CredentialQuery | undefined

		if (this.querySchema) {
			let p = this.querySchema.safeParse(req.query)
			if (!p.success) {
				return r.error(new Error("Parsing query", {cause: p.error}))
			}
			q = p.data
		}

		let h: CredentialHeader | undefined

		if (this.headerSchema) {
			let p = this.headerSchema.safeParse(req.headers)
			if (!p.success) {
				return r.error(new Error("Parsing header", {cause: p.error}))
			}
			h = p.data
		}

		let errs: Error[] = []

		// todo: do not register an error if q.baseUrl === h.baseUrl

		if (q && q.baseUrl !== undefined && h && h.baseUrl !== undefined) {
			errs.push(new Error("Both query and header specify base URL"))
		}

		if (errs.length !== 0) {
			return r.error(new errors.Errors({cause: errs}))
		}

		let c: Credential = {
			baseUrl: "",
			apiKey: "",
			pat: "",
			username: "",
			password: "",
		}

		if (q && q.baseUrl !== undefined) {
			c.baseUrl = q.baseUrl
		} else if (h && h.baseUrl !== undefined) {
			c.baseUrl = h.baseUrl
		}

		if (h && h.apiKey !== undefined) {
			c.apiKey = h.apiKey
		}

		if (h && h.pat !== undefined) {
			c.pat = h.pat
		}

		if (h && h.username !== undefined) {
			c.username = h.username
		}

		if (h && h.password !== undefined) {
			c.password = h.password
		}

		// todo: validate that username has password and vice versa

		let w = Boolean(c.apiKey)
		let x = Boolean(c.pat)
		let y = Boolean(c.username) && Boolean(c.password)
		let z = Number(w) + Number(x) + Number(y)

		if (z !== 0 && z !== 1) {
			errs.push(new Error("Expected only one of API key, PAT, or (username and password) to be set"))
		}

		if (z !== 0 && !c.baseUrl) {
			errs.push(new Error("Base URL is required with API key, PAT, or (username and password)"))
		}

		if (errs.length !== 0) {
			return r.error(new errors.Errors({cause: errs}))
		}

		return r.ok(c)
	}
}

export class InternalCredentialParser {
	requestHeaders: string[]

	constructor() {
		this.requestHeaders = [
			"Authorization",
			"Referer",
		]
	}

	parse(req: express.Request): r.Result<Credential, Error> {
		let a = req.headers.authorization
		if (!a) {
			return r.error(new Error("Authorization header is required"))
		}

		let f = req.headers.referer
		if (!f) {
			return r.error(new Error("Referer header is required"))
		}

		let b = r.safeNew(URL, f)
		if (b.err) {
			return r.error(new Error("Creating base URL", {cause: b.err}))
		}

		if (!b.v.pathname.endsWith("/")) {
			b.v.pathname += "/"
		}

		let c: Credential = {
			baseUrl: b.v.href,
			apiKey: "",
			pat: a,
			username: "",
			password: "",
		}

		return r.ok(c)
	}
}
