/**
 * @module
 * @mergeModuleWith util/mcp
 */

import type * as server from "@modelcontextprotocol/sdk/server/index.js"
import type * as protocol from "@modelcontextprotocol/sdk/shared/protocol.js"
import * as types from "@modelcontextprotocol/sdk/types.js"
import type * as z from "zod"
import * as errors from "../errors.ts"
import * as result from "../result.ts"

export type CallToolRequest = z.infer<typeof types.CallToolRequestSchema>

export type CallToolRequestDefinition<
	R extends types.ServerRequest = types.ServerRequest,
	N extends types.ServerNotification = types.ServerNotification,
	T extends types.ServerResult = types.ServerResult,
> = RequestDefinition<R, N, T, typeof types.CallToolRequestSchema>

export type ListToolsRequestDefinition<
	R extends types.ServerRequest = types.ServerRequest,
	N extends types.ServerNotification = types.ServerNotification,
	T extends types.ServerResult = types.ServerResult,
> = RequestDefinition<R, N, T, typeof types.ListToolsRequestSchema>

export type RequestSchema<
	M extends string = string,
> = z.ZodObject<{method: z.ZodLiteral<M>}>

export type RequestExtra<
	R extends types.ServerRequest = types.ServerRequest,
	N extends types.ServerNotification = types.ServerNotification,
> = protocol.RequestHandlerExtra<R, N>

export type RequestDefinition<
	R extends types.ServerRequest = types.ServerRequest,
	N extends types.ServerNotification = types.ServerNotification,
	T extends types.ServerResult = types.ServerResult,
	S extends RequestSchema = RequestSchema,
> = {
	schema: S
	handler(this: void, request: z.infer<S>, extra: RequestExtra<R, N>): T | Promise<T>
}

export function register(
	s: server.Server,
	defs: RequestDefinition[],
): result.Result<void, Error> {
	let errs: Error[] = []

	for (let d of defs) {
		let r = result.safeSync(
			s.assertCanSetRequestHandler.bind(s),
			d.schema.shape.method.value,
		)
		if (r.err) {
			errs.push(r.err)
			continue
		}

		if (d.schema === types.CallToolRequestSchema) {
			s.registerCapabilities({tools: {}})
			s.setRequestHandler(d.schema, d.handler)
			continue
		}

		if (d.schema === types.ListToolsRequestSchema) {
			s.registerCapabilities({tools: {}})
			s.setRequestHandler(d.schema, d.handler)
			continue
		}

		errs.push(new Error(`Unsupported schema: ${d.schema.shape.method.value}`))
	}

	if (errs.length !== 0) {
		return result.error(new errors.Errors({cause: errs}))
	}

	return result.ok()
}
