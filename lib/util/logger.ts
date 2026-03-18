/**
 * @module util/logger
 */

import type * as types from "@modelcontextprotocol/sdk/types.js"
import logfmt from "logfmt"
import * as context from "./context.ts"
import * as errors from "./errors.ts"
import * as mcp from "./mcp.ts"
import * as strings from "./strings.ts"
import * as trace from "./trace.ts"

type Payload = object & {
	time?: string
	level?: string
	msg?: string
	requestId?: string
	mcpSessionId?: string
	mcpRequestId?: types.RequestId
	mcpTaskId?: string
	mcpProgressToken?: string | number
}

export type LoggerWritable = {
	write(data: string): void
}

export class Logger {
	private stdout: LoggerWritable
	private stderr: LoggerWritable

	constructor(stdout: LoggerWritable, stderr: LoggerWritable) {
		this.stdout = stdout
		this.stderr = stderr
	}

	info(m: string, o?: object): void {
		this.log(this.stdout, "INF", m, o)
	}

	warn(m: string, o?: object): void {
		this.log(this.stdout, "WRN", m, o)
	}

	error(m: string, o?: object): void {
		this.log(this.stderr, "ERR", m, o)
	}

	mute(): void {
		this.log = () => {}
	}

	private log(w: LoggerWritable, l: string, m: string, o?: object): void {
		let ctx = context.get()

		let now = new Date()

		let p: Payload = {
			time: now.toISOString(),
			level: l,
			msg: m,
			requestId: ctx[trace.requestIdKey],
			mcpSessionId: ctx[mcp.sessionIdKey],
			mcpRequestId: ctx[mcp.requestIdKey],
			mcpTaskId: ctx[mcp.taskIdKey],
			mcpProgressToken: ctx[mcp.progressTokenKey],
			...o,
		}

		let d = format(p)

		logfmt.log(d, w)
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
