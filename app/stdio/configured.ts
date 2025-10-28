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

import * as stdio from "@modelcontextprotocol/sdk/server/stdio.js"
import * as api from "../../lib/api.ts"
import * as mcp from "../../lib/mcp.ts"
import * as utilFetch from "../../lib/util/fetch.ts"
import * as logger from "../../lib/util/logger.ts"
import * as utilMcp from "../../lib/util/mcp.ts"
import * as result from "../../lib/util/result.ts"
import type * as config from "../config.ts"
import * as shared from "../shared.ts"

export function start(g: config.global.Config): [shared.P, shared.Cleanup] {
	let x: logger.ContextProvider = {
		get() {
			// eslint-disable-next-line unicorn/no-useless-undefined
			return undefined
		},
	}

	let s = shared.createServer()

	let e = new logger.ServerLogger(x, s)

	s.registerCapabilities({logging: {}})

	let f = utilFetch.withLogger(x, e, fetch)

	let cc: api.ClientConfig = {
		userAgent: g.api.userAgent,
		baseUrl: g.api.shared.baseUrl,
		fetch: f,
	}

	let c = new api.Client(cc)

	if (g.api.shared.authorization) {
		c = c.withAuth(g.api.shared.authorization)
	}

	if (g.api.shared.apiKey) {
		c = c.withApiKey(g.api.shared.apiKey)
	}

	if (g.api.shared.pat) {
		c = c.withAuthToken(g.api.shared.pat)
	}

	if (g.api.shared.username && g.api.shared.password) {
		c = c.withBasicAuth(g.api.shared.username, g.api.shared.password)
	}

	let sc: mcp.ConfiguredServerConfig = {
		client: c,
		resolver: new api.Resolver(c),
		uploader: new api.Uploader(c),
		dynamic: g.mcp.dynamic,
		tools: g.mcp.tools,
	}

	let defs = mcp.configuredServer(sc)

	utilMcp.register(s, defs)

	let t = new stdio.StdioServerTransport()

	let cleanup: shared.Cleanup = async() => {
		let r = await result.safeAsync(t.close.bind(s))
		if (r.err) {
			return new Error("Closing transport", {cause: r.err})
		}
	}

	let p: shared.P = new Promise((res) => {
		s.connect(t).
			// eslint-disable-next-line promise/prefer-await-to-then
			then(() => {
				res(undefined)
				return
			}).
			// eslint-disable-next-line promise/prefer-await-to-then
			catch((err: unknown) => {
				res(new Error("Attaching server", {cause: err}))
			})
	})

	return [p, cleanup]
}
