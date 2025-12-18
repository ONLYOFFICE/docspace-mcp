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

import * as z from "zod"
import type * as core from "zod/v4/core"
import * as result from "./result.ts"

export function wrapUnion<
	A extends readonly [z.ZodLiteral<string>, z.ZodLiteral<string>, ...z.ZodLiteral<string>[]],
>(v: z.ZodUnion<A>, f: string): z.ZodUnion<A> {
	let a: z.core.SomeType[] = []

	for (let o of v.options) {
		if (o.values.size !== 0) {
			let [v] = o.values

			let c = z.literal(`${f}.${v}`)

			if (o.description) {
				c = c.describe(o.description)
			}

			a.push(c)
		}
	}

	return z.union(a as unknown as A)
}

export function unionToEnum<T extends string | number>(
	u: z.ZodUnion<readonly [z.ZodLiteral<T>, z.ZodLiteral<T>, ...z.ZodLiteral<T>[]]>,
	d: string,
): T extends string ? z.ZodString : T extends number ? z.ZodNumber : never {
	let t: z.ZodString | z.ZodNumber | undefined
	let r: Record<string, T> = {}
	let c = ""

	let errs: Error[] = []

	if (u.options.length === 0) {
		errs.push(new Error("Union has no options"))
	} else {
		for (let o of u.options) {
			if (o.values.size !== 1) {
				errs.push(new Error("Union option must have exactly one literal value"))
			} else {
				let [v] = o.values

				if (t) {
					if (typeof v !== t.type) {
						errs.push(new Error("Union options must have consistent types"))
					}
				} else {
					switch (typeof v) {
					case "string":
						t = z.string()
						break
					case "number":
						t = z.number()
						break
					default:
						errs.push(new Error("Union option type must be string or number"))
						break
					}
				}

				let k = `_${v}`

				if (k in r) {
					errs.push(new Error("Duplicate value in union options"))
				} else {
					r[k] = v

					if (o.description) {
						c += `${v} - ${o.description}\n`
					}
				}
			}
		}
	}

	if (errs.length !== 0) {
		throw new Error("Converting union to enum", {cause: errs})
	}

	if (!t) {
		throw new Error("Could not determine union type")
	}

	if (c !== "") {
		c = c.slice(0, -1)
	}

	if (d !== "" && c !== "") {
		c = `${d}\n\n${c}`
	} else if (d !== "") {
		c = d
	}

	let e = z.enum(r)

	if (c !== "") {
		e = e.describe(c)
	}

	t = t.superRefine((v, ctx) => {
		let p = e.safeParse(v)
		if (!p.success) {
			for (let i of p.error.issues) {
				ctx.addIssue(i as core.$ZodSuperRefineIssue)
			}
		}
	})

	if (c !== "") {
		t = t.describe(c)
	}

	// It is hard to write the return type without using any.
	// eslint-disable-next-line typescript/no-explicit-any
	return t as any
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
			code: "custom",
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
				code: "custom",
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
				code: "custom",
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
				code: "custom",
				message: `Expected a valid URL, but got ${v}`,
				fatal: true,
			})
			return z.NEVER
		}

		if (r.v.search) {
			c.addIssue({
				code: "custom",
				message: `Expected a URL without search parameters, but got ${v}`,
			})
		}

		if (r.v.hash) {
			c.addIssue({
				code: "custom",
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
					code: "custom",
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
			code: "custom",
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
					code: "custom",
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
