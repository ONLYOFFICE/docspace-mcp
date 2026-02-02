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
