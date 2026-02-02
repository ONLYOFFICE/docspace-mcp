/**
 * @module
 * @mergeModuleWith util/logger
 */

import logfmt from "logfmt"
import * as errors from "../errors.ts"
import * as strings from "../strings.ts"

export type Writable = {
	write(data: string): void
}

export class VanillaLogger {
	private w: Writable

	constructor(w: Writable) {
		this.w = w
	}

	info(msg: string, o?: object): void {
		this.log("INF", msg, o)
	}

	warn(msg: string, o?: object): void {
		this.log("WRN", msg, o)
	}

	error(msg: string, o?: object): void {
		this.log("ERR", msg, o)
	}

	mute(): void {
		this.log = () => {}
	}

	private log(level: string, msg: string, o?: object): void {
		let v: object = {time: new Date().toISOString(), level, msg, ...o}
		let r = format(v)
		logfmt.log(r, this.w)
	}
}

function format(v: object): Record<string, unknown> {
	let s: Record<string, unknown> = {}
	for (let [p, e] of Object.entries(v)) {
		next(s, p, e)
	}
	return s

	function next(o: Record<string, unknown>, k: string, v: unknown): void {
		if (v === null || v === undefined) {
			return
		}

		if (typeof v === "boolean" || typeof v === "number") {
			o[strings.camelCaseToSnakeCase(k)] = v
			return
		}

		if (typeof v === "string") {
			o[strings.camelCaseToSnakeCase(k)] = strings.escapeWhitespace(v)
			return
		}

		if (Array.isArray(v)) {
			o[strings.camelCaseToSnakeCase(k)] = strings.escapeWhitespace(v.join(","))
			return
		}

		if (v instanceof Error) {
			let m = errors.format(v)
			o[strings.camelCaseToSnakeCase(k)] = strings.escapeWhitespace(m)
			return
		}

		if (typeof v === "object") {
			for (let [p, e] of Object.entries(v)) {
				next(o, `${k}.${p}`, e)
			}
			return
		}
	}
}
