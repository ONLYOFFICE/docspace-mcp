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
import z from "zod"
import * as r from "../util/result.ts"
import {JwsHeaderSchema, JwtClaimsSchema} from "./shared.ts"

export class InvalidAuthTokenError extends Error {
	constructor(...args: ConstructorParameters<typeof Error>) {
		super(...args)
		this.name = "InvalidAuthTokenError"
	}
}

export const AuthTokenPayloadSchema = z.object({
	exp: z.number().optional(),
	nbf: z.number(),
	iat: z.number(),
	hdr: JwsHeaderSchema,
	pld: JwtClaimsSchema,
	sgn: z.string(),
})

export type AuthTokenPayload = z.infer<typeof AuthTokenPayloadSchema>

export type AuthTokensConfig = {
	algorithm: AuthTokensAlgorithm
	ttl: number
	secretKey: string
}

export type AuthTokensAlgorithm = "HS256" | "HS384" | "HS512" | ""

export class AuthTokens {
	private algorithm: AuthTokensAlgorithm
	private ttl: number
	private secretKey: string

	constructor(config: AuthTokensConfig) {
		if (!config.algorithm || !config.secretKey) {
			this.algorithm = ""
			this.secretKey = ""
		} else {
			this.algorithm = config.algorithm
			this.secretKey = config.secretKey
		}

		this.ttl = config.ttl
	}

	decode(t: string): r.Result<[string, AuthTokenPayload], Error> {
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

		let jw = r.safeSync(verify, t, this.secretKey, vo)
		if (jw.err) {
			return r.error(new InvalidAuthTokenError("Verifying token", {cause: jw.err}))
		}

		if (typeof jw.v === "string") {
			return r.error(new Error("Invalid options"))
		}

		if (typeof jw.v.payload === "string") {
			return r.error(new InvalidAuthTokenError("Invalid payload"))
		}

		let tp = AuthTokenPayloadSchema.safeParse(jw.v.payload)
		if (!tp.success) {
			return r.error(new InvalidAuthTokenError("Parsing payload", {cause: tp.error}))
		}

		// Use objects directly from the payload to preserve field order.
		let tt = `${base64url(jw.v.payload.hdr)}.${base64url(jw.v.payload.pld)}.${jw.v.payload.sgn}`

		return r.ok([tt, tp.data])
	}

	encode(t: string): r.Result<[string, AuthTokenPayload], Error> {
		let co: jwt.DecodeOptions = {
			complete: true,
		}

		let jw = decode(t, co)
		if (!jw) {
			return r.error(new InvalidAuthTokenError("Invalid token"))
		}

		if (typeof jw === "string") {
			return r.error(new Error("Invalid options"))
		}

		if (typeof jw.payload === "string") {
			return r.error(new InvalidAuthTokenError("Invalid payload"))
		}

		let iat = Math.floor(Date.now() / 1000)

		let exp: number | undefined

		if (this.ttl) {
			exp = iat + this.ttl / 1000
		} else {
			exp = 0
		}

		if (jw.payload.exp && (!exp || jw.payload.exp < exp)) {
			exp = jw.payload.exp
		}

		if (exp && exp < iat) {
			exp = iat
		}

		let tp: AuthTokenPayload = {
			exp,
			nbf: iat,
			iat,
			hdr: jw.header,
			pld: jw.payload,
			sgn: jw.signature,
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

		let tt = r.safeSync(sign, tp, this.secretKey, so)
		if (tt.err) {
			return r.error(new Error("Signing token", {cause: tt.err}))
		}

		return r.ok([tt.v, tp])
	}
}

function decode(t: string, o: jwt.DecodeOptions): jwt.Jwt | jwt.JwtPayload | string | null {
	return jwt.decode(t, o)
}

function sign(p: object, k: string, o: jwt.SignOptions): string {
	return jwt.sign(p, k, o)
}

function verify(t: string, k: string, o: jwt.VerifyOptions): jwt.Jwt | jwt.JwtPayload | string {
	return jwt.verify(t, k, o)
}

function base64url(v: unknown): string {
	return Buffer.from(JSON.stringify(v)).toString("base64url")
}
