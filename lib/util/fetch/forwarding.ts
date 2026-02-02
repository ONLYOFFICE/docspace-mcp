/**
 * @module
 * @mergeModuleWith util/fetch
 */

/* eslint-disable typescript/consistent-type-definitions */

import type * as context from "../context.ts"

export type ForwardingContextProvider = {
	get(): context.Context | undefined
}

export function withForwarding(cp: ForwardingContextProvider, fetch: typeof globalThis.fetch): typeof globalThis.fetch {
	return async(input, init) => {
		let ctx = cp.get()

		if (ctx && (ctx.forwardedFor || ctx.realIp)) {
			if (!(input instanceof Request)) {
				throw new Error(`Invalid input type "${typeof input}"`)
			}

			input = input.clone()

			if (ctx.forwardedFor) {
				input.headers.set("X-Forwarded-For", ctx.forwardedFor)
			}

			if (ctx.realIp) {
				input.headers.set("X-Real-IP", ctx.realIp)
			}
		}

		return await fetch(input, init)
	}
}
