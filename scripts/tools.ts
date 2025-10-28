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

import type * as mcp from "../lib/util/mcp.ts"

export function sortToolsets(toolsets: mcp.ToolsetInfo[]): mcp.ToolsetInfo[] {
	toolsets = toolsets.sort((a, b) => {
		return a.name.localeCompare(b.name)
	})

	for (let s of toolsets) {
		s.tools = sortTools(s.tools)
	}

	return toolsets
}

export function sortTools<T extends mcp.Summary>(tools: T[]): T[] {
	return tools.sort((a, b) => {
		return a.name.localeCompare(b.name)
	})
}
