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
 * @mergeModuleWith util/fetch
 */

/* eslint-disable typescript/consistent-type-definitions */

import type * as context from "../context.ts"

export type ForwardingContextProvider = {
	get(): context.Context | undefined
}

export function withForwarding(cp: ForwardingContextProvider, fetch: typeof globalThis.fetch): typeof globalThis.fetch {
	return async(input, init) => {
		let ctx = cp.get()

		if (ctx && (ctx.forwardedFor || ctx.realIp)) {
			if (!(input instanceof Request)) {
				throw new Error(`Invalid input type "${typeof input}"`)
			}

			input = input.clone()

			if (ctx.forwardedFor) {
				input.headers.set("X-Forwarded-For", ctx.forwardedFor)
			}

			if (ctx.realIp) {
				input.headers.set("X-Real-IP", ctx.realIp)
			}
		}

		return await fetch(input, init)
	}
}
