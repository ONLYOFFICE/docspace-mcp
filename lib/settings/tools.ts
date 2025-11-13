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
 * @mergeModuleWith settings
 */

/* eslint-disable typescript/consistent-type-definitions */

import * as mcp from "../mcp.ts"

export type ResolveToolsOptions = {
	toolsets: string[]
	enabledTools: string[]
	disabledTools: string[]
}

export type ResolveToolsResult = {
	toolsets: string[]
	tools: string[]
}

// todo: the behavior of this function is unclear
export function resolveTools(o: ResolveToolsOptions): ResolveToolsResult {
	let x: string[] = []
	let y: string[] = []

	for (let n of o.toolsets) {
		x.push(n)

		for (let s of mcp.toolsetInfos) {
			if (s.name === n) {
				for (let t of s.tools) {
					y.push(t.name)
				}
				break
			}
		}
	}

	for (let n of o.enabledTools) {
		for (let s of mcp.toolsetInfos) {
			let h = false
			for (let t of s.tools) {
				if (t.name === n) {
					h = true
					break
				}
			}

			if (h) {
				if (!x.includes(s.name)) {
					x.push(s.name)
				}
				break
			}
		}

		if (!y.includes(n)) {
			y.push(n)
		}
	}

	for (let n of o.disabledTools) {
		let i = y.indexOf(n)
		if (i !== -1) {
			y.splice(i, 1)
		}
	}

	for (let sn of x) {
		for (let s of mcp.toolsetInfos) {
			if (s.name === sn) {
				let h = false

				for (let tn of y) {
					for (let t of s.tools) {
						if (t.name === tn) {
							h = true
							break
						}
					}

					if (h) {
						break
					}
				}

				if (!h) {
					let i = x.indexOf(sn)
					if (i !== -1) {
						x.splice(i, 1)
					}
				}

				break
			}
		}
	}

	let r: ResolveToolsResult = {
		toolsets: x,
		tools: y,
	}

	return r
}
