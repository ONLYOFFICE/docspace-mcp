/**
 * @module
 * @mergeModuleWith util/express
 */

import type express from "express"
import type * as utilContext from "../context.ts"

declare module "../context.ts" {
	// eslint-disable-next-line typescript/consistent-type-definitions
	interface Context {
		forwardedFor?: string
		realIp?: string
		sessionId?: string
	}
}

export type ContextRunner = {
	run(cp: utilContext.Context, cb: () => void): void
}

export function context(cp: ContextRunner): express.Handler {
	let get = (req: express.Request, key: string): string => {
		let h = req.headers[key]

		if (!h || h.length === 0) {
			return ""
		}

		if (Array.isArray(h)) {
			return h[0]
		}

		return h
	}

	return (req, _, next) => {
		let xff = get(req, "x-forwarded-for")

		if (req.socket.remoteAddress) {
			if (xff) {
				xff += ", "
			}
			xff += req.socket.remoteAddress
		}

		let xri = get(req, "x-real-ip")

		if (!xri && req.ip) {
			xri = req.ip
		}

		let msi = get(req, "mcp-session-id")

		let ctx: utilContext.Context = {}

		if (xff) {
			ctx.forwardedFor = xff
		}

		if (xri) {
			ctx.realIp = xri
		}

		if (msi) {
			ctx.sessionId = msi
		}

		cp.run(ctx, () => {
			next()
		})
	}
}
