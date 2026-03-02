/**
 * @module
 * @mergeModuleWith util/forwarded
 */

import type express from "express"
import * as context from "../context.ts"
import * as http from "../http.ts"
import {forwardedForKey, realIpKey} from "./context.ts"

export function expressHandler(): express.Handler {
	return (req, _, next) => {
		let ff = http.header(req, "X-Forwarded-For")

		if (req.socket.remoteAddress) {
			if (ff) {
				ff += ", "
			}
			ff += req.socket.remoteAddress
		}

		let ri = http.header(req, "X-Real-IP")

		if (!ri && req.ip) {
			ri = req.ip
		}

		let ctx: context.Context = {}

		if (ff) {
			ctx[forwardedForKey] = ff
		}

		if (ri) {
			ctx[realIpKey] = ri
		}

		if (Object.getOwnPropertySymbols(ctx).length !== 0) {
			context.run(ctx, next)
			return
		}

		next()
	}
}
