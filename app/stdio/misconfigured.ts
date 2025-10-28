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
import * as mcp from "../../lib/mcp.ts"
import * as utilMcp from "../../lib/util/mcp.ts"
import * as result from "../../lib/util/result.ts"
import * as shared from "../shared.ts"

export function start(err: Error): [shared.P, shared.Cleanup] {
	let s = shared.createServer()

	let defs = mcp.misconfiguredServer(err)

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
