/**
 * @module
 * @mergeModuleWith mcp
 */

import * as types from "@modelcontextprotocol/sdk/types.js"
import * as errors from "../util/errors.ts"
import type * as mcp from "../util/mcp.ts"
import {toolsetInfos} from "./data.ts"

class MisconfiguredServer {
	err: Error
	toolInfos: mcp.ToolInfo[]

	constructor(err: Error) {
		this.err = err
		this.toolInfos = []

		for (let s of toolsetInfos) {
			this.toolInfos.push(...s.tools)
		}
	}

	listTools(): types.ListToolsResult {
		return {
			tools: this.toolInfos,
		}
	}

	callTool(): types.CallToolResult {
		return {
			content: [
				{
					type: "text",
					text: errors.format(this.err),
				},
			],
			isError: true,
		}
	}
}

export function misconfiguredServer(
	err: Error,
): mcp.RequestDefinition[] {
	let s = new MisconfiguredServer(err)

	let l: mcp.ListToolsRequestDefinition = {
		schema: types.ListToolsRequestSchema,
		handler: s.listTools.bind(s),
	}

	let c: mcp.CallToolRequestDefinition = {
		schema: types.CallToolRequestSchema,
		handler: s.callTool.bind(s),
	}

	return [l, c]
}
