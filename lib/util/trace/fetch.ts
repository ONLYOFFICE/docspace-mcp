/**
 * @module
 * @mergeModuleWith util/trace
 */

import * as context from "../context.ts"
import {requestIdKey} from "./context.ts"

export function wrapFetch(fetch: typeof globalThis.fetch): typeof globalThis.fetch {
	return async(input, init) => {
		let ctx = context.get()

		if (ctx && ctx[requestIdKey]) {
			if (!(input instanceof Request)) {
				throw new Error("Input is not a Request instance")
			}

			input = input.clone()

			input.headers.set("X-Request-ID", ctx[requestIdKey])
		}

		return await fetch(input, init)
	}
}
