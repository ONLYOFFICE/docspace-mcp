/**
 * (c) Copyright Ascensio System SIA 2025
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @license
 */

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

// eslint-disable-next-line typescript/consistent-type-definitions
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
