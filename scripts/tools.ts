import type * as mcp from "../lib/util/mcp.ts"

export function sortToolsets(toolsets: mcp.Toolset[]): mcp.Toolset[] {
	toolsets = toolsets.sort((a, b) => {
		return a.name.localeCompare(b.name)
	})

	for (let s of toolsets) {
		s.tools = sortTools(s.tools)
	}

	return toolsets
}

export function sortTools<T extends mcp.ToolSummary>(tools: T[]): T[] {
	return tools.sort((a, b) => {
		return a.name.localeCompare(b.name)
	})
}
