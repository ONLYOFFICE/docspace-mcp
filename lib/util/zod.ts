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
 * @module util/zod
 */

/* eslint-disable no-underscore-dangle */

import * as z from "zod"
import * as result from "./result.ts"

export function wrapUnion<
	A extends [z.ZodLiteral<string>, z.ZodLiteral<string>, ...z.ZodLiteral<string>[]],
>(v: z.ZodUnion<A>, f: string): z.ZodUnion<A> {
	let a = [] as unknown as A
	for (let o of v.options) {
		let c = z.literal(`${f}.${o._def.value}`)
		if (o._def.description !== undefined) {
			c = c.describe(o._def.description)
		}
		a.push(c)
	}
	return z.union(a)
}

export function stringUnionToEnum<
	A extends [z.ZodLiteral<string>, z.ZodLiteral<string>, ...z.ZodLiteral<string>[]],
>(u: z.ZodUnion<A>, d: string): z.ZodEnum<[string, ...string[]]> {
	let a = [] as unknown as [string, ...string[]]
	let c = ""

	for (let o of u.options) {
		a.push(o._def.value)
		if (o._def.description !== undefined) {
			c += `${o._def.value} - ${o._def.description}\n`
		}
	}

	if (c !== "") {
		c = c.slice(0, -1)
	}

	if (d !== "" && c !== "") {
		c = `${d}\n\n${c}`
	} else if (d !== "") {
		c = d
	}

	let e = z.enum(a)

	if (c !== "") {
		e = e.describe(c)
	}

	return e
}

export function numberUnionToEnum<
	A extends [z.ZodLiteral<number>, z.ZodLiteral<number>, ...z.ZodLiteral<number>[]],
>(u: z.ZodUnion<A>, d: string): z.ZodNativeEnum<z.EnumLike> {
	let r: z.EnumLike = {}
	let c = ""

	for (let o of u.options) {
		r[`_${o._def.value}`] = o._def.value
		if (o._def.description !== undefined) {
			c += `${o._def.value} - ${o._def.description}\n`
		}
	}

	if (c !== "") {
		c = c.slice(0, -1)
	}

	if (d !== "" && c !== "") {
		c = `${d}\n\n${c}`
	} else if (d !== "") {
		c = d
	}

	let e = z.nativeEnum(r)

	if (c !== "") {
		e = e.describe(c)
	}

	return e
}

// eslint-disable-next-line stylistic/max-len
export function envOptionalBoolean(): (v: string | undefined, c: z.RefinementCtx) => boolean | undefined | never {
	return (v, c) => {
		if (v === undefined) {
			return
		}
		return envBoolean()(v, c)
	}
}

export function envBoolean(): (v: string, c: z.RefinementCtx) => boolean | never {
	return (v, c) => {
		let t = v.trim().toLowerCase()
		if (!t) {
			return false
		}

		if (t === "yes" || t === "y" || t === "true" || t === "1") {
			return true
		}

		if (t === "no" || t === "n" || t === "false" || t === "0") {
			return false
		}

		c.addIssue({
			code: z.ZodIssueCode.custom,
			message: `Expected one of: yes, y, true, 1, no, n, false, 0, but got ${v}`,
			fatal: true,
		})

		return z.NEVER
	}
}

export function envNumber(): (v: string, c: z.RefinementCtx) => number | never {
	return (v, c) => {
		let t = v.trim()
		if (!t) {
			return 0
		}

		let n = Number.parseInt(t, 10)
		if (Number.isNaN(n)) {
			c.addIssue({
				code: z.ZodIssueCode.custom,
				message: `Expected a number, but got ${v}`,
				fatal: true,
			})
			return z.NEVER
		}

		return n
	}
}

export function envUrl(): (v: string, c: z.RefinementCtx) => string | never {
	return (v, c) => {
		let t = v.trim()
		if (!t) {
			return ""
		}

		let r = result.safeNew(URL, t)
		if (r.err) {
			c.addIssue({
				code: z.ZodIssueCode.custom,
				message: `Expected a valid URL, but got ${v}`,
				fatal: true,
			})
			return z.NEVER
		}

		return r.v.toString()
	}
}

// eslint-disable-next-line stylistic/max-len
export function envOptionalBaseUrl(): (v: string | undefined, c: z.RefinementCtx) => string | undefined | never {
	return (v, c) => {
		if (v === undefined) {
			return
		}
		return envBaseUrl()(v, c)
	}
}

export function envBaseUrl(): (v: string, c: z.RefinementCtx) => string | never {
	return (v, c) => {
		let t = v.trim()
		if (!t) {
			return ""
		}

		let r = result.safeNew(URL, t)
		if (r.err) {
			c.addIssue({
				code: z.ZodIssueCode.custom,
				message: `Expected a valid URL, but got ${v}`,
				fatal: true,
			})
			return z.NEVER
		}

		if (r.v.search) {
			c.addIssue({
				code: z.ZodIssueCode.custom,
				message: `Expected a URL without search parameters, but got ${v}`,
			})
		}

		if (r.v.hash) {
			c.addIssue({
				code: z.ZodIssueCode.custom,
				message: `Expected a URL without hash, but got ${v}`,
			})
		}

		if (!r.v.pathname.endsWith("/")) {
			r.v.pathname += "/"
		}

		return r.v.toString()
	}
}

export function envUrlList(): (v: string, c: z.RefinementCtx) => string[] | never {
	return (v, c) => {
		let a: string[] = []

		for (let u of v.split(",")) {
			let t = u.trim()
			if (!t) {
				continue
			}

			let r = result.safeNew(URL, t)
			if (r.err) {
				c.addIssue({
					code: z.ZodIssueCode.custom,
					message: `Expected a valid URL, but got ${u}`,
				})
				continue
			}

			let s = r.v.toString()
			if (!a.includes(s)) {
				a.push(s)
			}
		}

		return a
	}
}

export function envUnion<T extends string>(a: T[]): (v: string, c: z.RefinementCtx) => T | never {
	return (v, c) => {
		for (let e of a) {
			if (e === v) {
				return e
			}
		}

		c.addIssue({
			code: z.ZodIssueCode.custom,
			message: `Expected one of: ${a.join(", ")}, but got ${v}`,
			fatal: true,
		})

		return z.NEVER
	}
}

// eslint-disable-next-line stylistic/max-len
export function envOptionalOptions(a: string[]): (v: string | undefined, c: z.RefinementCtx) => string[] | undefined | never {
	return (v, c) => {
		if (v === undefined) {
			return
		}
		return envOptions(a)(v, c)
	}
}

export function envOptions(a: string[]): (v: string, c: z.RefinementCtx) => string[] | never {
	return (v, c) => {
		let e: string[] = []
		let f: string[] = []
		let g: string[] = []

		for (let u of v.split(",")) {
			let t = u.trim().toLowerCase()
			if (!t) {
				continue
			}

			let h = false
			for (let n of a) {
				if (n === t) {
					h = true
					break
				}
			}

			if (!h && !f.includes(t)) {
				f.push(t)
				g.push(u)
			}
			if (h && !e.includes(t)) {
				e.push(t)
			}
		}

		if (g.length !== 0) {
			for (let u of g) {
				c.addIssue({
					code: z.ZodIssueCode.custom,
					message: `Unknown value: ${u}`,
				})
			}
			return z.NEVER
		}

		return e
	}
}

export function envList(): (v: string, c: z.RefinementCtx) => string[] {
	return (v) => {
		let a: string[] = []

		for (let u of v.split(",")) {
			let t = u.trim()
			if (!t) {
				continue
			}

			if (!a.includes(t)) {
				a.push(t)
			}
		}

		return a
	}
}
