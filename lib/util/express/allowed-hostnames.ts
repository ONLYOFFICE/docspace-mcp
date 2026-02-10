/**
 * @module
 * @mergeModuleWith util/express
 */

import type express from "express"
import * as r from "../result.ts"

export type AllowedHostnamesCallback = (req: express.Request, res: express.Response, err: Error) => void

export function allowedHostnames(hostnames: string[], cb: AllowedHostnamesCallback): express.Handler {
	return (req, res, next) => {
		let err: Error | undefined

		if (req.headers.host) {
			let u = r.safeNew(URL, `http://${req.headers.host}`)
			if (u.err) {
				err = new Error("Parsing Host header", {cause: u.err})
			} else if (!hostnames.includes(u.v.hostname)) {
				err = new Error(`Hostname ${u.v.hostname} is not allowed`)
			}
		} else {
			err = new Error("Host header is missing")
		}

		if (err) {
			res.status(405)

			cb(req, res, err)

			if (!res.writableEnded) {
				res.end()
			}
		} else {
			next()
		}
	}
}
