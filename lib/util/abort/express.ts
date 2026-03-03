/**
 * @module
 * @mergeModuleWith util/abort
 */

import type express from "express"
import * as context from "../context.ts"
import {signalKey} from "./context.ts"

export function expressHandler(): express.Handler {
	return (_, res, next) => {
		let ac = new AbortController()

		let onClose = (): void => {
			ac.abort(new DOMException("Request closed", "AbortError"))
		}

		res.once("close", onClose)

		let ctx: context.Context = {
			[signalKey]: ac.signal,
		}

		context.run(ctx, next)
	}
}
