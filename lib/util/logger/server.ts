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
 * @mergeModuleWith util/logger
 */

import type * as types from "@modelcontextprotocol/sdk/types.js"
import type * as context from "../context.ts"
import * as errors from "../errors.ts"
import * as result from "../result.ts"
import * as strings from "../strings.ts"

type Level = types.LoggingMessageNotification["params"]["level"]

export interface ContextProvider {
	get(): context.Context | undefined
}

export interface Server {
	sendLoggingMessage(
		data: types.LoggingMessageNotification["params"],
		sessionId?: string
	): Promise<void>
}

export class ServerLogger {
	private p: ContextProvider
	private s: Server

	constructor(p: ContextProvider, s: Server) {
		this.p = p
		this.s = s
	}

	async info(msg: string, o?: object): Promise<void> {
		await this.log("info", msg, o)
	}

	async warn(msg: string, o?: object): Promise<void> {
		await this.log("warning", msg, o)
	}

	async error(msg: string, o?: object): Promise<void> {
		await this.log("error", msg, o)
	}

	private async log(level: Level, msg: string, o?: object): Promise<void> {
		let id: string | undefined

		let c = this.p.get()
		if (c && c.sessionId) {
			id = c.sessionId
		}

		let v: object = {
			msg,
			...o,
		}

		let r = format(v)

		let _ = await result.safeAsync(
			this.s.sendLoggingMessage.bind(this.s),
			{
				level,
				data: r,
			},
			id,
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
