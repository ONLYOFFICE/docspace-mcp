/**
 * @module
 * @mergeModuleWith util/mcp
 */

import type * as types from "@modelcontextprotocol/sdk/types.js"
import * as z from "zod"

export type ToolsetDefinition = Summary & {
	tools: ToolDefinition[]
}

export type ToolsetInfo = Summary & {
	tools: ToolInfo[]
}

export type ToolDefinition = Summary & {
	inputSchema?: z.ZodObject<z.ZodRawShape>
	outputSchema?: z.ZodObject<z.ZodRawShape>
}

export type ToolInfo = Summary & {
	inputSchema: ToolInputSchema
	outputSchema?: ToolOutputSchema
}

// eslint-disable-next-line typescript/consistent-type-definitions
export type Summary = {
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

export function toToolsetInfos(defs: ToolsetDefinition[]): ToolsetInfo[] {
	let infos: ToolsetInfo[] = []

	for (let d of defs) {
		let i: ToolsetInfo = {
			name: d.name,
			description: d.description,
			tools: toToolInfos(d.tools),
		}
		infos.push(i)
	}

	return infos
}

export function toToolInfos(defs: ToolDefinition[]): ToolInfo[] {
	let infos: ToolInfo[] = []

	for (let d of defs) {
		let inputSchema: z.ZodObject<z.ZodRawShape> | undefined

		if (d.inputSchema) {
			inputSchema = d.inputSchema
		} else {
			inputSchema = z.object({})
		}

		let i: ToolInfo = {
			name: d.name,
			description: d.description,
			inputSchema: z.toJSONSchema(inputSchema) as ToolOutputSchema,
		}

		if (d.outputSchema) {
			i.outputSchema = z.toJSONSchema(d.outputSchema) as ToolOutputSchema
		}

		infos.push(i)
	}

	return infos
}
