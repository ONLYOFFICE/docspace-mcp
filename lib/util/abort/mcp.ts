/**
 * @module
 * @mergeModuleWith util/abort
 */

import * as context from "../context.ts"
import type * as mcp from "../mcp.ts"
import {signalKey} from "./context.ts"
import {Controller} from "./controller.ts"

export type McpHandler = Parameters<mcp.Protocol["setRequestHandler"]>[1]

export function wrapMcpHandler(handler: McpHandler): McpHandler {
	return async(req, extra) => {
		let ctx = context.get()

		let ac = new Controller()

		if (ctx && ctx[signalKey]) {
			ac.withSignal(ctx[signalKey])
		}

		ac.withSignal(extra.signal)

		ctx = {
			[signalKey]: ac.signal,
		}

		let ex = (res: (v: Awaited<ReturnType<McpHandler>>) => void, rej: (err: unknown) => void): void => {
			let cb = (): void => {
				void (async() => {
					try {
						res(await handler(req, extra))
					} catch (err) {
						rej(err)
					} finally {
						ac.clear()
					}
				})()
			}

			context.run(ctx, cb)
		}

		return await new Promise(ex)
	}
}
