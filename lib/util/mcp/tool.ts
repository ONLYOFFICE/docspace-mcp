/**
 * @module
 * @mergeModuleWith util/mcp
 */

import type * as types from "@modelcontextprotocol/sdk/types.js"

export type Toolset = ToolSummary & {
	tools: Tool[]
}

export type Tool = ToolSummary & {
	inputSchema: ToolInputSchema
	outputSchema?: ToolOutputSchema
	annotations?: ToolAnnotations
}

export type ToolSummary = {
	name: string
	description: string
}

export type ToolInputSchema = Exclude<
	types.ListToolsResult["tools"][0]["inputSchema"],
	undefined
>

export type ToolOutputSchema = Exclude<
	types.ListToolsResult["tools"][0]["outputSchema"],
	undefined
>

export type ToolAnnotations = Exclude<
	types.ListToolsResult["tools"][0]["annotations"],
	undefined
>
