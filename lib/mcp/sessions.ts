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

import * as errors from "../util/errors.ts"
import * as result from "../util/result.ts"

export interface Session {
	id: string
	transport: SessionTransport
	createdAt: Date
	expiresAt: Date
}

export interface SessionTransport {
	close(): Promise<void>
}

export interface SessionsConfig {
	ttl: number
}

export interface SessionsCreateOptions {
	id: string
	transport: SessionTransport
}

export class Sessions {
	private ttl: number
	private m = new Map<string, Session>()

	constructor(config: SessionsConfig) {
		this.ttl = config.ttl
	}

	create(o: SessionsCreateOptions): result.Result<Session, Error> {
		let createdAt = new Date()

		let expiresAt: Date

		if (this.ttl === 0) {
			expiresAt = new Date(0)
		} else {
			expiresAt = new Date(createdAt.getTime() + this.ttl)
		}

		let s: Session = {
			id: o.id,
			transport: o.transport,
			createdAt,
			expiresAt,
		}

		this.m.set(s.id, s)

		s = {...s}

		return result.ok(s)
	}

	get(id: string): result.Result<Session, Error> {
		let s = this.m.get(id)
		if (!s) {
			return result.error(new Error(`Session ${id} not found`))
		}

		let a = new Date()

		let b = s.expiresAt

		if (b.getTime() !== 0 && a.getTime() >= b.getTime()) {
			return result.error(new Error(`Session ${s.id} has expired`))
		}

		s = {...s}

		return result.ok(s)
	}

	delete(id: string): Error | undefined {
		if (!this.m.delete(id)) {
			return new Error(`Session ${id} could not be deleted`)
		}
	}

	async close(id: string): Promise<Error | undefined> {
		let s = this.m.get(id)
		if (!s) {
			return new Error(`Session ${id} not found`)
		}

		let r = await result.safeAsync(s.transport.close.bind(s.transport))
		if (r.err) {
			return new Error(`Closing transport for session ${s.id}`, {cause: r.err})
		}
	}

	async expire(id: string): Promise<Error | undefined> {
		let s = this.m.get(id)
		if (!s) {
			return new Error(`Session ${id} not found`)
		}

		let a = new Date()
		if (Number.isNaN(a.getTime())) {
			return new Error("Current date is invalid")
		}

		let b = s.expiresAt
		if (Number.isNaN(b.getTime())) {
			return new Error("Expiration date is invalid")
		}

		if (a.getTime() < b.getTime()) {
			return
		}

		let err = await this.close(id)
		if (err) {
			return new Error(`Closing session ${s.id}`, {cause: err})
		}
	}

	async clear(): Promise<Error | undefined> {
		let errs: Error[] = []

		for (let id of this.m.keys()) {
			let err = await this.close(id)
			if (err) {
				errs.push(new Error(`Closing session ${id}`, {cause: err}))
			}
		}

		if (errs.length !== 0) {
			return new errors.Errors({cause: errs})
		}
	}

	async watch(sig: AbortSignal, interval: number): Promise<Error | undefined> {
		if (sig.aborted) {
			return new DOMException("Aborted", "AbortError")
		}

		if (interval === 0) {
			return
		}

		return await new Promise((res) => {
			let t = setInterval(tick.bind(this), interval)
			sig.addEventListener("abort", abort)

			function tick(this: Sessions): void {
				void (async() => {
					for (let id of this.m.keys()) {
						let err = await this.expire(id)
						if (err) {
							rej(new Error(`Expiring session ${id}`, {cause: err}))
						}
					}
				})()
			}

			function abort(): void {
				rej(new DOMException("Aborted", "AbortError"))
			}

			function rej(err: Error): void {
				clearInterval(t)
				sig.removeEventListener("abort", abort)
				res(err)
			}
		})
	}
}
