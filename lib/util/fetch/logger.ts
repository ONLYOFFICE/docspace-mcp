/**
 * @module
 * @mergeModuleWith util/fetch
 */

import type * as context from "../context.ts"

const outgoing = "<--"
const incoming = "-->"
const error = "xxx"

type Payload = {
	sessionId?: string
	method?: string
	url?: string
	status?: number
	duration?: string
	err?: unknown
}

export type ContextProvider = {
	get(): context.Context | undefined
}

export type Logger = {
	info(msg: string, o?: object): void | Promise<void>
	warn(msg: string, o?: object): void | Promise<void>
	error(msg: string, o?: object): void | Promise<void>
}

export function withLogger(
	p: ContextProvider,
	l: Logger,
	f: typeof fetch,
): typeof fetch {
	return async function fetch(input, init) {
		let o: Payload = {}

		let c = p.get()
		if (c && c.sessionId) {
			o.sessionId = c.sessionId
		}

		if (input instanceof Request) {
			o.method = input.method
			o.url = input.url
		}

		try {
			await l.info(incoming, o)

			let s = Date.now()

			let r = await f(input, init)

			o.status = r.status

			let d = Date.now() - s
			if (d < 1000) {
				o.duration = `${d}ms`
			} else {
				o.duration = `${Math.round(d / 1000)}s`
			}

			await l.info(outgoing, o)

			return r
		} catch (err) {
			o.err = err

			await l.error(error, o)

			throw err
		}
	}
}
