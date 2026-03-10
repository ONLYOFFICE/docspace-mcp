/**
 * @module
 * @mergeModuleWith util/mcp
 */

import type * as protocol from "@modelcontextprotocol/sdk/shared/protocol.js"
import * as types from "@modelcontextprotocol/sdk/types.js"
import * as context from "../context.ts"
import * as errors from "../errors.ts"
import * as r from "../result.ts"
import * as strings from "../strings.ts"
import * as trace from "../trace.ts"
import {progressTokenKey, requestIdKey, sessionIdKey, taskIdKey} from "./context.ts"
import type {Router} from "./router.ts"

type Payload = object & {
	time?: string
	msg?: string
	requestId?: string
	mcpSessionId?: string
	mcpRequestId?: types.RequestId
	mcpTaskId?: string
	mcpProgressToken?: string | number
}

export type LoggerProtocol = {
	getServerCapabilities(): types.ServerCapabilities
	notification(notification: types.Notification, options?: protocol.NotificationOptions): Promise<void>
}

export class Logger {
	private protocol: LoggerProtocol

	private level: types.LoggingLevel = "info"

	constructor(protocol: LoggerProtocol) {
		this.protocol = protocol
	}

	router(): Router {
		return {
			capabilities: {
				logging: {},
			},
			handlers: {
				"logging/setLevel": this.handleSetLevel.bind(this),
			},
		}
	}

	private handleSetLevel(req: types.SetLevelRequest): types.Result {
		this.level = req.params.level
		return {}
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

	private async log(l: types.LoggingLevel, m: string, o?: object): Promise<void> {
		let sc = this.protocol.getServerCapabilities()

		if (!sc.logging) {
			return
		}

		let a = types.LoggingLevelSchema.options.indexOf(this.level)
		let b = types.LoggingLevelSchema.options.indexOf(l)

		if (a > b) {
			return
		}

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

		let n: types.Notification = {
			method: "notifications/message",
			params: {
				level: l,
				data: format(p),
			},
		}

		let no: protocol.NotificationOptions = {}

		if (ctx[requestIdKey] !== undefined) {
			no.relatedRequestId = ctx[requestIdKey]
		}

		if (ctx[taskIdKey]) {
			no.relatedTask = {taskId: ctx[taskIdKey]}
		}

		let _ = await r.safeAsync(
			this.protocol.notification.bind(this.protocol),
			n,
			no,
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
