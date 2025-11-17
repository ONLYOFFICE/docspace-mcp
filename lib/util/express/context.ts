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
 * @mergeModuleWith util/express
 */

/* eslint-disable typescript/consistent-type-definitions */

import type express from "express"
import type * as utilContext from "../context.ts"

declare module "../context.ts" {
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
