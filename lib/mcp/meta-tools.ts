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
 * @mergeModuleWith mcp
 */

import * as z from "zod"
import type * as mcp from "../util/mcp.ts"
import type {Result} from "../util/result.ts"
import {error, ok} from "../util/result.ts"
import type {ConfiguredServer, ConfiguredServerRouteToolResult} from "./configured-server.ts"

export const ListToolsInputSchema = z.object({
	toolset: z.string().describe("The name of the toolset to list tools from."),
})

export const GetToolInputSchemaInputSchema = z.object({
	tool: z.string().describe("The name of the tool to get input schema for."),
})

export const GetToolOutputSchemaInputSchema = z.object({
	tool: z.string().describe("The name of the tool to get output schema for."),
})

export const CallToolInputSchema = z.object({
	tool: z.string().describe("The name of the tool to call."),
	input: z.looseObject({}).optional().describe("The value that corresponds to the input schema of the tool."),
})

export class MetaTools {
	private s: ConfiguredServer

	constructor(s: ConfiguredServer) {
		this.s = s
	}

	listToolsets(): Result<mcp.Summary[], Error> {
		let summaries: mcp.Summary[] = []

		for (let t of this.s.toolsetInfos) {
			let s: mcp.Summary = {
				name: t.name,
				description: t.description,
			}
			summaries.push(s)
		}

		if (summaries.length === 0) {
			return error(new Error("No toolsets found."))
		}

		return ok(summaries)
	}

	listTools(req: mcp.CallToolRequest): Result<mcp.Summary[], Error> {
		let pr = ListToolsInputSchema.safeParse(req.params.arguments)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let s: mcp.ToolsetInfo | undefined

		for (let t of this.s.toolsetInfos) {
			if (t.name === pr.data.toolset) {
				s = t
				break
			}
		}

		if (!s) {
			return error(new Error(`Toolset '${pr.data.toolset}' not found.`))
		}

		let summaries: mcp.Summary[] = []

		for (let t of s.tools) {
			let s: mcp.Summary = {
				name: t.name,
				description: t.description,
			}
			summaries.push(s)
		}

		if (summaries.length === 0) {
			return error(new Error(`No tools found for toolset '${pr.data.toolset}'.`))
		}

		return ok(summaries)
	}

	getToolInputSchema(
		req: mcp.CallToolRequest,
	): Result<mcp.ToolInputSchema, Error> {
		let pr = GetToolInputSchemaInputSchema.safeParse(req.params.arguments)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let i: mcp.ToolInputSchema | undefined

		for (let x of this.s.toolsetInfos) {
			for (let y of x.tools) {
				if (y.name === pr.data.tool) {
					i = y.inputSchema
					break
				}
			}

			if (i) {
				break
			}
		}

		if (!i) {
			return error(new Error(`Tool '${pr.data.tool}' not found.`))
		}

		return ok(i)
	}

	getToolOutputSchema(
		req: mcp.CallToolRequest,
	): Result<mcp.ToolOutputSchema, Error> {
		let pr = GetToolInputSchemaInputSchema.safeParse(req.params.arguments)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let o: mcp.ToolOutputSchema | undefined

		for (let x of this.s.toolsetInfos) {
			for (let y of x.tools) {
				if (y.name === pr.data.tool) {
					o = y.outputSchema
					break
				}
			}

			if (o) {
				break
			}
		}

		if (!o) {
			return error(new Error(`Tool '${pr.data.tool}' not found.`))
		}

		return ok(o)
	}

	async callTool(
		req: mcp.CallToolRequest,
		extra: mcp.RequestExtra,
	): Promise<Result<ConfiguredServerRouteToolResult, Error>> {
		let pr = CallToolInputSchema.safeParse(req.params.arguments)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		req = {
			...req,
			params: {
				...req.params,
			},
		}

		req.params.name = pr.data.tool
		req.params.arguments = pr.data.input

		let cr = await this.s.routeRegularTool(req, extra)
		if (cr.err) {
			return error(new Error("Routing tool.", {cause: cr.err}))
		}

		return ok(cr.v)
	}
}
