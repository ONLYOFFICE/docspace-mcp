/**
 * @module
 * @mergeModuleWith util/express
 */

import type express from "express"
import type * as context from "../context.ts"

const outgoing = "<--"
const incoming = "-->"

interface Payload {
	sessionId?: string
	method?: string
	url?: string
	status?: number
	duration?: string
}

export interface ContextProvider {
	get(): context.Context | undefined
}

export interface Logger {
	info(msg: string, o?: object): void
	warn(msg: string, o?: object): void
	error(msg: string, o?: object): void
}

export function logger(p: ContextProvider, l: Logger): express.Handler {
	return (req, res, next) => {
		let o: Payload = {}

		let c = p.get()
		if (c && c.sessionId) {
			o.sessionId = c.sessionId
		}

		o.method = req.method
		o.url = req.url

		l.info(incoming, o)

		let s = Date.now()

		res.on("finish", () => {
			o.status = res.statusCode

			let d = Date.now() - s
			if (d < 1000) {
				o.duration = `${d}ms`
			} else {
				o.duration = `${Math.round(d / 1000)}s`
			}

			l.info(outgoing, o)
		})

		next()
	}
}
