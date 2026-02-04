/**
 * @module util/errors
 */

import * as z from "zod"

export class JsonError extends Error {
	name: "JsonError"

	constructor(message: string, options?: ErrorOptions) {
		super(message, options)
		this.name = "JsonError"
	}

	toObject(): object {
		return {
			message: format(this),
		}
	}
}

export class JsonrpcError extends Error {
	name: "JsonrpcError"
	code: number

	constructor(code: number, message: string, options?: ErrorOptions) {
		super(message, options)
		this.name = "JsonrpcError"
		this.code = code
	}

	toObject(): object {
		return {
			jsonrpc: "2.0",
			error: {
				code: this.code,
				message: format(this),
			},
			id: null,
		}
	}
}

export class MessageError extends Error {
	name: "MessageError"

	constructor(message: string, options?: ErrorOptions) {
		super(message, options)
		this.name = "MessageError"
	}

	toString(): string {
		return format(this)
	}
}

export function isAborted(err: unknown): boolean {
	if (!(err instanceof Error)) {
		return false
	}

	if (err instanceof DOMException && err.name === "AbortError") {
		return true
	}

	if (err.cause && Array.isArray(err.cause)) {
		for (let e of err.cause) {
			if (isAborted(e)) {
				return true
			}
		}
	}

	if (err.cause) {
		return isAborted(err.cause)
	}

	return false
}

export function as<
	A extends unknown[],
	R,
>(
	err: unknown,
	t: new (...args: A) => R,
): R | undefined {
	if (err instanceof Error) {
		if (err.constructor === t) {
			return err as unknown as R
		}

		if (err.cause) {
			let a = as(err.cause, t)
			if (a) {
				return a
			}
			return
		}

		return
	}

	if (Array.isArray(err)) {
		for (let e of err) {
			let a = as(e, t)
			if (a) {
				return a
			}
		}
		return
	}
}

export function format(err: Error): string {
	let m = ""
	let l = 0

	loop(err)

	if (m.length !== 0) {
		m = m.slice(0, -1)
	}

	return m

	function loop(err: unknown): void {
		if (err instanceof z.ZodError) {
			l += 1

			for (let i of err.issues) {
				let p = ""

				for (let e of i.path) {
					if (typeof e === "number") {
						p += `[${e}]`
					} else {
						p += `.${e.toString()}`
					}
				}

				if (p.length !== 0) {
					p = p.slice(1)
				}

				if (p.length === 0) {
					add(`${i.code}: ${i.message}`)
				} else {
					add(`${p}: ${i.code} ${i.message}`)
				}
			}

			l -= 1
			return
		}

		if (err instanceof AggregateError) {
			loop(err.errors)
			return
		}

		if (err instanceof Error) {
			add(err.message)
			if (err.cause) {
				l += 1
				loop(err.cause)
				l -= 1
			}
			return
		}

		if (Array.isArray(err)) {
			for (let e of err) {
				loop(e)
			}
			return
		}
	}

	function add(s: string): void {
		m += `${"\t".repeat(l)}${s}\n`
	}
}
