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
 * @mergeModuleWith mcp
 */

import * as sse from "@modelcontextprotocol/sdk/server/sse.js"
import type * as express from "express"
import * as result from "../util/result.ts"
import type {Session, SessionsCreateOptions} from "./sessions.ts"

export interface SseTransportsConfig {
	logger: SseTransportsLogger
	sessions: SseTransportsSessions
}

export interface SseTransportsLogger {
	info(msg: string, o?: object): void
	error(msg: string, o?: object): void
}

export interface SseTransportsSessions {
	create(o: SessionsCreateOptions): result.Result<Session, Error>
	get(id: string): result.Result<Session, Error>
	delete(id: string): Error | undefined
}

export class SseTransports {
	private logger: SseTransportsLogger
	private sessions: SseTransportsSessions

	constructor(config: SseTransportsConfig) {
		this.logger = config.logger
		this.sessions = config.sessions
	}

	create(endpoint: string, res: express.Response): sse.SSEServerTransport {
		let t = new sse.SSEServerTransport(endpoint, res)

		// https://github.com/modelcontextprotocol/typescript-sdk/blob/1.17.0/src/server/sse.ts#L101
		let w = res.writeHead.bind(res)

		// @ts-ignore
		res.writeHead = (statusCode, statusMessage, headers) => {
			if (statusCode === 200) {
				let o: SessionsCreateOptions = {
					id: t.sessionId,
					transport: t,
				}

				let s = this.sessions.create(o)
				if (s.err) {
					this.logger.error("Creating session", {sessionId: t.sessionId, err: s.err})
				} else {
					this.logger.info("Session created", {sessionId: s.v.id})
				}
			}

			let r = w(statusCode, statusMessage, headers)

			res.writeHead = w

			return r
		}

		t.onclose = () => {
			let err = this.sessions.delete(t.sessionId)
			if (err) {
				this.logger.error("Deleting session", {sessionId: t.sessionId, err})
			} else {
				this.logger.info("Session deleted", {sessionId: t.sessionId})
			}
		}

		return t
	}

	retrieve(id: string): result.Result<sse.SSEServerTransport, Error> {
		let s = this.sessions.get(id)
		if (s.err) {
			return result.error(new Error("Getting session", {cause: s.err}))
		}

		if (!(s.v.transport instanceof sse.SSEServerTransport)) {
			return result.error(new Error("Session transport is not a SSEServerTransport"))
		}

		return result.ok(s.v.transport)
	}
}
