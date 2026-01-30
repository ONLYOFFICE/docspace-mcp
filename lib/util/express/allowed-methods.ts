/**
 * @module
 * @mergeModuleWith util/express
 */

import type express from "express"

export type AllowedMethodsCallback = (req: express.Request, res: express.Response) => void

export function allowedMethods(methods: string[], cb: AllowedMethodsCallback): express.Handler {
	let am = methods.join(", ")

	return (req, res, next) => {
		if (methods.includes(req.method)) {
			next()
			return
		}

		res.status(405)
		res.set("Allow", am)

		cb(req, res)

		if (!res.writableEnded) {
			res.end()
		}
	}
}
