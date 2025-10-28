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

import * as streamableHttp from "@modelcontextprotocol/sdk/server/streamableHttp.js"
import * as result from "../util/result.ts"
import type {Session, SessionsCreateOptions} from "./sessions.ts"

export interface StreamableTransportsConfig {
	logger: StreamableTransportsLogger
	sessions: StreamableTransportsSessions
}

export interface StreamableTransportsLogger {
	info(msg: string, o?: object): void
	warn(msg: string, o?: object): void
	error(msg: string, o?: object): void
}

export interface StreamableTransportsSessions {
	create(o: SessionsCreateOptions): result.Result<Session, Error>
	get(id: string): result.Result<Session, Error>
	delete(id: string): Error | undefined
}

export class StreamableTransports {
	private logger: StreamableTransportsLogger
	private sessions: StreamableTransportsSessions

	constructor(config: StreamableTransportsConfig) {
		this.logger = config.logger
		this.sessions = config.sessions
	}

	create(): streamableHttp.StreamableHTTPServerTransport {
		let t = new streamableHttp.StreamableHTTPServerTransport({
			sessionIdGenerator: () => {
				return crypto.randomUUID()
			},
			onsessioninitialized: (sessionId) => {
				let o: SessionsCreateOptions = {
					id: sessionId,
					transport: t,
				}

				let s = this.sessions.create(o)
				if (s.err) {
					this.logger.error("Creating session", {sessionId, err: s.err})
					return
				}

				this.logger.info("Session created", {sessionId: s.v.id})
			},
		})

		t.onclose = () => {
			if (!t.sessionId) {
				this.logger.warn("Transport closed without a session ID")
				return
			}

			let err = this.sessions.delete(t.sessionId)
			if (err) {
				this.logger.error("Deleting session", {sessionId: t.sessionId, err})
				return
			}

			this.logger.info("Session deleted", {sessionId: t.sessionId})
		}

		return t
	}

	retrieve(id: string): result.Result<streamableHttp.StreamableHTTPServerTransport, Error> {
		let s = this.sessions.get(id)
		if (s.err) {
			return result.error(new Error("Getting session", {cause: s.err}))
		}

		if (!(s.v.transport instanceof streamableHttp.StreamableHTTPServerTransport)) {
			return result.error(new Error("Session transport is not a StreamableHTTPServerTransport"))
		}

		return result.ok(s.v.transport)
	}
}
