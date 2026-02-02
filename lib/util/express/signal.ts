/**
 * @module
 * @mergeModuleWith util/express
 */

import type express from "express"

declare module "express-serve-static-core" {
	// eslint-disable-next-line typescript/consistent-type-definitions
	interface Request {
		signal?: AbortSignal
	}
}

export function signal(): express.Handler {
	return (req, res, next) => {
		let ac = new AbortController()

		if (req.signal) {
			req.signal.addEventListener(
				"abort",
				() => {
					ac.abort()
				},
				{
					once: true,
				},
			)
		}

		req.signal = ac.signal

		res.once("close", () => {
			ac.abort()
		})

		next()
	}
}
