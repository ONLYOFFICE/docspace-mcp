/**
 * @module
 * @mergeModuleWith util/mcp
 */

import type * as types from "@modelcontextprotocol/sdk/types.js"

declare module "../context.ts" {
	// eslint-disable-next-line typescript/consistent-type-definitions
	interface Context {
		[progressTokenKey]?: string | number
		[requestIdKey]?: types.RequestId
		[sessionIdKey]?: string
		[taskIdKey]?: string
	}
}

export const progressTokenKey = Symbol("progressToken")
export const requestIdKey = Symbol("requestId")
export const sessionIdKey = Symbol("sessionId")
export const taskIdKey = Symbol("taskId")
