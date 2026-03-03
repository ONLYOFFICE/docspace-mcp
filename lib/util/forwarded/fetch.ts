/**
 * @module
 * @mergeModuleWith util/forwarded
 */

import * as context from "../context.ts"
import {forwardedForKey, realIpKey} from "./context.ts"

export function wrapFetch(fetch: typeof globalThis.fetch): typeof globalThis.fetch {
	return async(input, init) => {
		let ctx = context.get()

		if (ctx && (ctx[forwardedForKey] || ctx[realIpKey])) {
			if (!(input instanceof Request)) {
				throw new Error("Input is not a Request instance")
			}

			input = input.clone()

			if (ctx[forwardedForKey]) {
				input.headers.set("X-Forwarded-For", ctx[forwardedForKey])
			}

			if (ctx[realIpKey]) {
				input.headers.set("X-Real-IP", ctx[realIpKey])
			}
		}

		return await fetch(input, init)
	}
}
