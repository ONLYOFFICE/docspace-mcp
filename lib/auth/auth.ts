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
import type * as oauth from "../oauth.ts"
import * as errors from "../util/errors.ts"
import type * as r from "../util/result.ts"
import type {Credential} from "./credential.ts"

declare module "express-serve-static-core" {
	interface Request {
		auth?: Auth
	}
}

export type ErrorResponse = {
	message: string
}

export type Auth = {
	baseUrl: string
	auth: string
	apiKey: string
	pat: string
	username: string
	password: string
}

export type AuthManagerConfig = {
	defaultBaseUrl: string
	defaultAuth: string
	defaultApiKey: string
	defaultPat: string
	defaultUsername: string
	defaultPassword: string
	oauthEnabled: boolean
	headerEnabled: boolean
	oauthAuthTokens: AuthManagerOauthAuthTokens
	oauthHandlerRequestHeaders: string[]
	oauthHandlerResponseHeaders: string[]
	oauthHandler: express.Handler
	credentialParserRequestHeaders: string[]
	credentialParser: AuthManagerCredentialParser
}

export type AuthManagerOauthAuthTokens = {
	decode(t: string): r.Result<[string, oauth.AuthTokenPayload], Error>
}

export type AuthManagerCredentialParser = {
	parse(req: express.Request): r.Result<Credential, Error>
}

export class AuthManager {
	private defaultBaseUrl: string
	private defaultAuth: string
	private defaultApiKey: string
	private defaultPat: string
	private defaultUsername: string
	private defaultPassword: string
	private oauthEnabled: boolean
	private headerEnabled: boolean
	private oauthAuthTokens: AuthManagerOauthAuthTokens
	private oauthHandler: express.Handler
	private credentialParser: AuthManagerCredentialParser

	requestHeaders: string[]
	responseHeaders: string[]

	constructor(config: AuthManagerConfig) {
		this.defaultBaseUrl = config.defaultBaseUrl
		this.defaultAuth = config.defaultAuth
		this.defaultApiKey = config.defaultApiKey
		this.defaultPat = config.defaultPat
		this.defaultUsername = config.defaultUsername
		this.defaultPassword = config.defaultPassword
		this.oauthEnabled = config.oauthEnabled
		this.headerEnabled = config.headerEnabled
		this.oauthAuthTokens = config.oauthAuthTokens
		this.oauthHandler = config.oauthHandler
		this.credentialParser = config.credentialParser

		let requestHeaders: string[] = []
		let responseHeaders: string[] = []

		if (config.oauthEnabled) {
			requestHeaders.push(...config.oauthHandlerRequestHeaders)
			responseHeaders.push(...config.oauthHandlerResponseHeaders)
		}

		requestHeaders.push(...config.credentialParserRequestHeaders)

		if (config.oauthEnabled || config.headerEnabled) {
			requestHeaders.push("Authorization")
		}

		responseHeaders.push("Content-Type")

		this.requestHeaders = [...new Set(requestHeaders)].sort()
		this.responseHeaders = [...new Set(responseHeaders)].sort()
	}

	handler(): express.Handler {
		let end = (res: express.Response, code: number, err: Error): void => {
			let er: ErrorResponse = {
				message: errors.format(err),
			}
			res.status(code)
			res.json(er)
		}

		return (req, res, next) => {
			let h = req.headers.authorization
			if (!h) {
				h = ""
			}

			let c = this.credentialParser.parse(req)
			if (c.err) {
				let err = new Error("Parsing credential", {cause: c.err})
				end(res, 400, err)
				return
			}

			if (this.oauthEnabled && h) {
				let a = parseAuthHeader(h)
				if (a.scheme === "bearer") {
					let d = this.oauthAuthTokens.decode(a.params)
					if (!d.err) {
						if (
							c.v.baseUrl === "" &&
							c.v.apiKey === "" &&
							c.v.pat === "" &&
							c.v.username === "" &&
							c.v.password === ""
						) {
							this.oauthHandler(req, res, next)
							return
						}

						let err = new Error("OAuth token with credentials")
						end(res, 400, err)
						return
					}
				}
			}

			if (this.headerEnabled && h) {
				if (
					c.v.baseUrl !== "" &&
					c.v.apiKey === "" &&
					c.v.pat === "" &&
					c.v.username === "" &&
					c.v.password === ""
				) {
					req.auth = {
						baseUrl: c.v.baseUrl,
						auth: h,
						apiKey: "",
						pat: "",
						username: "",
						password: "",
					}
					next()
					return
				}

				let err = new Error("Authorization header with credentials")
				end(res, 400, err)
				return
			}

			if (c.v.baseUrl !== "") {
				if (
					c.v.apiKey !== "" ||
					c.v.pat !== "" ||
					c.v.username !== "" ||
					c.v.password !== ""
				) {
					req.auth = {
						baseUrl: c.v.baseUrl,
						auth: "",
						apiKey: c.v.apiKey,
						pat: c.v.pat,
						username: c.v.username,
						password: c.v.password,
					}
					next()
					return
				}

				let err = new Error("Base URL without credentials")
				end(res, 400, err)
				return
			}

			if (this.oauthEnabled) {
				this.oauthHandler(req, res, next)
				return
			}

			if (this.defaultBaseUrl !== "") {
				req.auth = {
					baseUrl: this.defaultBaseUrl,
					auth: this.defaultAuth,
					apiKey: this.defaultApiKey,
					pat: this.defaultPat,
					username: this.defaultUsername,
					password: this.defaultPassword,
				}
				next()
				return
			}

			let err = new Error("Unauthorized")
			end(res, 401, err)
		}
	}
}

type AuthHeader = {
	scheme: string
	params: string
}

function parseAuthHeader(h: string): AuthHeader {
	let i = h.indexOf(" ")

	let s: string | undefined
	let p: string | undefined

	if (i === -1) {
		s = ""
		p = h
	} else {
		s = h.slice(0, i).toLowerCase()
		p = h.slice(i + 1)
	}

	let a: AuthHeader = {
		scheme: s.toLowerCase(),
		params: p,
	}

	return a
}
