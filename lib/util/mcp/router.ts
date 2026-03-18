/**
 * @module
 * @mergeModuleWith util/mcp
 */

import type * as types from "@modelcontextprotocol/sdk/types.js"
import type {RequestHandlerMap} from "./request.ts"

export type Router = {
	capabilities: types.ServerCapabilities
	handlers: Partial<RequestHandlerMap>
}
