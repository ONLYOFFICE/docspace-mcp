/**
 * @module
 * @mergeModuleWith util/mcp
 */

import type * as protocol from "@modelcontextprotocol/sdk/shared/protocol.js"
import type * as types from "@modelcontextprotocol/sdk/types.js"
import * as abort from "../abort.ts"
import * as context from "../context.ts"
import * as r from "../result.ts"
import {progressTokenKey, requestIdKey, taskIdKey} from "./context.ts"

export type ProgressProtocol = {
	notification(notification: types.Notification, options?: protocol.NotificationOptions): Promise<void>
}

export class Progress {
	private protocol: ProgressProtocol

	constructor(protocol: ProgressProtocol) {
		this.protocol = protocol
	}

	async notify(p: number, m: string): Promise<void> {
		let ctx = context.get()

		if (ctx[abort.signalKey] && ctx[abort.signalKey].aborted) {
			return
		}

		if (ctx[progressTokenKey] === undefined) {
			return
		}

		let n: types.Notification = {
			method: "notifications/progress",
			params: {
				progressToken: ctx[progressTokenKey],
				progress: p,
				total: 100,
				message: m,
			},
		}

		let o: protocol.NotificationOptions = {}

		if (ctx[requestIdKey] !== undefined) {
			o.relatedRequestId = ctx[requestIdKey]
		}

		if (ctx[taskIdKey]) {
			o.relatedTask = {taskId: ctx[taskIdKey]}
		}

		let _ = await r.safeAsync(
			this.protocol.notification.bind(this.protocol),
			n,
			o,
		)
	}
}
