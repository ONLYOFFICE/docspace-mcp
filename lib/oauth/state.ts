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

import jwt from "jsonwebtoken"
import * as z from "zod"
import * as r from "../util/result.ts"

export class InvalidStateTokenError extends Error {
	constructor(...args: ConstructorParameters<typeof Error>) {
		super(...args)
		this.name = "InvalidStateTokenError"
	}
}

export const StateTokenPayloadSchema = z.object({
	exp: z.number().optional(),
	nbf: z.number(),
	iat: z.number(),
	redirect_uri: z.string(),
	state: z.string().optional(),
})

export type State = {
	redirect_uri: string
	state?: string | undefined
}

export type StateTokenPayload = z.infer<typeof StateTokenPayloadSchema>

export type StateTokensConfig = {
	algorithm: StateTokensAlgorithm
	ttl: number
	secretKey: string
}

export type StateTokensAlgorithm = "HS256" | "HS384" | "HS512" | ""

export class StateTokens {
	private algorithm: StateTokensAlgorithm
	private ttl: number
	private secretKey: string

	constructor(config: StateTokensConfig) {
		if (!config.algorithm || !config.secretKey) {
			this.algorithm = ""
			this.secretKey = ""
		} else {
			this.algorithm = config.algorithm
			this.secretKey = config.secretKey
		}

		this.ttl = config.ttl
	}

	verify(t: string): r.Result<State, Error> {
		let alg: jwt.Algorithm | undefined

		if (this.algorithm) {
			alg = this.algorithm
		} else {
			alg = "none"
		}

		let vo: jwt.VerifyOptions = {
			algorithms: [alg],
			complete: true,
		}

		let jw = r.safeSync(jwt.verify, t, this.secretKey, vo)
		if (jw.err) {
			return r.error(new InvalidStateTokenError("Verifying token", {cause: jw.err}))
		}

		if (typeof jw.v === "string") {
			return r.error(new Error("Invalid options"))
		}

		if (typeof jw.v.payload === "string") {
			return r.error(new InvalidStateTokenError("Invalid payload"))
		}

		let tp = StateTokenPayloadSchema.safeParse(jw.v.payload)
		if (!tp.success) {
			return r.error(new InvalidStateTokenError("Parsing payload", {cause: tp.error}))
		}

		let st: State = {
			redirect_uri: tp.data.redirect_uri,
		}

		if (tp.data.state) {
			st.state = tp.data.state
		}

		return r.ok(st)
	}

	encode(s: State): r.Result<string, Error> {
		let iat = Math.floor(Date.now() / 1000)

		let exp: number | undefined

		if (this.ttl) {
			exp = iat + this.ttl / 1000
		} else {
			exp = 0
		}

		let tp: StateTokenPayload = {
			exp,
			nbf: iat,
			iat,
			redirect_uri: s.redirect_uri,
		}

		if (s.state) {
			tp.state = s.state
		}

		if (!tp.exp) {
			delete tp.exp
		}

		let alg: jwt.Algorithm | undefined

		if (this.algorithm) {
			alg = this.algorithm
		} else {
			alg = "none"
		}

		let so: jwt.SignOptions = {
			algorithm: alg,
		}

		let tt = r.safeSync(jwt.sign, tp, this.secretKey, so)
		if (tt.err) {
			return r.error(new Error("Signing token", {cause: tt.err}))
		}

		return r.ok(tt.v)
	}
}
