/**
 * @module
 * @mergeModuleWith mcp
 */

import * as sse from "@modelcontextprotocol/sdk/server/sse.js"
import type * as express from "express"
import * as result from "../util/result.ts"
import type {Session, SessionsCreateOptions} from "./sessions.ts"

export type SseTransportsConfig = {
	logger: SseTransportsLogger
	sessions: SseTransportsSessions
}

export type SseTransportsLogger = {
	info(msg: string, o?: object): void
	error(msg: string, o?: object): void
}

export type SseTransportsSessions = {
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
