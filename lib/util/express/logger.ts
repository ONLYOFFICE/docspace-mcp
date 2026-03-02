/**
 * @module
 * @mergeModuleWith util/express
 */

import type express from "express"

const outgoing = "<--"
const incoming = "-->"

type Payload = {
	method?: string
	url?: string
	status?: number
	duration?: string
}

export type Logger = {
	info(m: string, o?: object): void
	warn(m: string, o?: object): void
	error(m: string, o?: object): void
}

export function logger(l: Logger): express.Handler {
	return (req, res, next) => {
		let o: Payload = {
			method: req.method,
			url: req.url,
		}

		l.info(incoming, o)

		let now = Date.now()

		let onFinish = (): void => {
			o.status = res.statusCode

			let d = Date.now() - now
			if (d < 1000) {
				o.duration = `${d}ms`
			} else {
				o.duration = `${Math.round(d / 1000)}s`
			}

			l.info(outgoing, o)

			res.removeListener("finish", onFinish)
		}

		res.addListener("finish", onFinish)

		next()
	}
}
