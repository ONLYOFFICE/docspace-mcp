/**
 * @module
 * @mergeModuleWith mcp
 */

import type * as types from "@modelcontextprotocol/sdk/types.js"
import * as errors from "../util/errors.ts"
import type * as mcp from "../util/mcp.ts"
import {toolsetInfos} from "./data.ts"

export class MisconfiguredServer {
	private err: Error
	private toolInfos: mcp.ToolInfo[]

	constructor(err: Error) {
		this.err = err
		this.toolInfos = []

		for (let s of toolsetInfos) {
			this.toolInfos.push(...s.tools)
		}
	}

	router(): mcp.Router {
		return {
			capabilities: {
				tools: {},
			},
			handlers: {
				"tools/call": this.callTool.bind(this),
				"tools/list": this.listTools.bind(this),
			},
		}
	}

	private listTools(): types.ListToolsResult {
		return {
			tools: this.toolInfos,
		}
	}

	private callTool(): types.CallToolResult {
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
