/**
 * @module
 * @mergeModuleWith util/mcp
 */

import type * as server from "@modelcontextprotocol/sdk/server/index.js"
import * as context from "../context.ts"
import {progressTokenKey, requestIdKey, taskIdKey} from "./context.ts"

export type McpHandler = Parameters<server.Server["setRequestHandler"]>[1]

export function wrapMcpHandler(handler: McpHandler): McpHandler {
	return async(req, extra) => {
		let ctx: context.Context = {}

		/* eslint-disable no-underscore-dangle */

		if (extra._meta && extra._meta.progressToken !== undefined) {
			ctx[progressTokenKey] = extra._meta.progressToken
		}

		ctx[requestIdKey] = extra.requestId

		if (extra.taskId) {
			ctx[taskIdKey] = extra.taskId
		}

		/* eslint-enable no-underscore-dangle */

		let ex = (res: (v: Awaited<ReturnType<McpHandler>>) => void, rej: (err: unknown) => void): void => {
			let cb = (): void => {
				void (async() => {
					try {
						res(await handler(req, extra))
					} catch (err) {
						rej(err)
					}
				})()
			}

			context.run(ctx, cb)
		}

		return await new Promise(ex)
	}
}
