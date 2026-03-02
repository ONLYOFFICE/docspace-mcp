/**
 * @module
 * @mergeModuleWith util/mcp
 */

import type * as types from "@modelcontextprotocol/sdk/types.js"
import * as context from "../context.ts"
import * as errors from "../errors.ts"
import * as r from "../result.ts"
import * as strings from "../strings.ts"
import * as trace from "../trace.ts"
import {progressTokenKey, requestIdKey, sessionIdKey, taskIdKey} from "./context.ts"

type Payload = object & {
	time?: string
	msg?: string
	requestId?: string
	mcpSessionId?: string
	mcpRequestId?: types.RequestId
	mcpTaskId?: string
	mcpProgressToken?: string | number
}

export type LoggerServer = {
	sendLoggingMessage(data: types.LoggingMessageNotification["params"], sessionId?: string): Promise<void>
}

export class Logger {
	private server: LoggerServer

	constructor(server: LoggerServer) {
		this.server = server
	}

	async info(m: string, o?: object): Promise<void> {
		await this.log("info", m, o)
	}

	async warn(m: string, o?: object): Promise<void> {
		await this.log("warning", m, o)
	}

	async error(m: string, o?: object): Promise<void> {
		await this.log("error", m, o)
	}

	private async log(l: types.LoggingMessageNotification["params"]["level"], m: string, o?: object): Promise<void> {
		let ctx = context.get()

		let now = new Date()

		let p: Payload = {
			time: now.toISOString(),
			msg: m,
			requestId: ctx[trace.requestIdKey],
			mcpSessionId: ctx[sessionIdKey],
			mcpRequestId: ctx[requestIdKey],
			mcpTaskId: ctx[taskIdKey],
			mcpProgressToken: ctx[progressTokenKey],
			...o,
		}

		let d: types.LoggingMessageNotification["params"] = {
			level: l,
			data: format(p),
		}

		let _ = await r.safeAsync(
			this.server.sendLoggingMessage.bind(this.server),
			d,
			ctx[sessionIdKey],
		)
	}
}

function format(v: object): Record<string, unknown> {
	return handle(v) as Record<string, unknown>

	function handle(v: unknown): unknown {
		if (v === null || v === undefined) {
			return
		}

		if (Array.isArray(v)) {
			let s: unknown[] = []

			for (let e of v) {
				let x = handle(e)
				if (x !== undefined) {
					s.push(x)
				}
			}

			if (s.length !== 0) {
				return s
			}

			return
		}

		if (v instanceof Error) {
			return errors.format(v)
		}

		if (typeof v === "object") {
			let o: Record<string, unknown> = {}

			for (let [p, e] of Object.entries(v)) {
				let x = handle(e)
				if (x !== undefined) {
					o[strings.camelCaseToSnakeCase(p)] = x
				}
			}

			if (Object.keys(o).length !== 0) {
				return o
			}

			return
		}

		return v
	}
}
