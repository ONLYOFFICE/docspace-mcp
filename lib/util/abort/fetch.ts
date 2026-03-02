/**
 * @module
 * @mergeModuleWith util/abort
 */

import * as context from "../context.ts"
import {signalKey} from "./context.ts"

export function wrapFetch(fetch: typeof globalThis.fetch): typeof globalThis.fetch {
	return async(input, init) => {
		let ctx = context.get()

		if (ctx && ctx[signalKey]) {
			if (!(input instanceof Request)) {
				throw new Error("Input is not a Request instance")
			}

			let ri: RequestInit = {
				signal: ctx[signalKey],
			}

			input = new Request(input, ri)
		}

		return await fetch(input, init)
	}
}
