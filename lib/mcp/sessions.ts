/**
 * @module
 * @mergeModuleWith mcp
 */

import * as errors from "../util/errors.ts"
import * as result from "../util/result.ts"

export type Session = {
	id: string
	transport: SessionTransport
	createdAt: Date
	expiresAt: Date
}

export type SessionTransport = {
	close(): Promise<void>
}

export type SessionsConfig = {
	ttl: number
}

export type SessionsCreateOptions = {
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
