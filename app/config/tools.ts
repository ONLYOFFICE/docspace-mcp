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

import * as mcp from "../../lib/mcp.ts"

export const availableToolsets = (() => {
	let a: string[] = ["all"]
	for (let s of mcp.toolsetInfos) {
		a.push(s.name)
	}
	return a
})()

export const availableTools = (() => {
	let a: string[] = []
	for (let s of mcp.toolsetInfos) {
		for (let t of s.tools) {
			a.push(t.name)
		}
	}
	return a
})()

export function normalizeToolsets(a: string[]): string[] {
	if (a.includes("all")) {
		a = [...availableToolsets]

		let i = a.indexOf("all")
		if (i !== -1) {
			a.splice(i, 1)
		}

		return a
	}

	return [...a]
}

export function resolveToolsetsAndTools(
	toolsets: string[],
	enabledTools: string[],
	disabledTools: string[],
): [string[], string[]] {
	let x: string[] = []
	let y: string[] = []

	for (let n of toolsets) {
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

	for (let n of enabledTools) {
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

	for (let n of disabledTools) {
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

	return [x, y]
}
