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

import * as types from "@modelcontextprotocol/sdk/types.js"
import type * as zodToJsonSchema from "zod-to-json-schema"
import * as api from "../api.ts"
import * as errors from "../util/errors.ts"
import type * as mcp from "../util/mcp.ts"
import * as result from "../util/result.ts"
import {metaToolInfos, toolsetInfos} from "./data.ts"
import {MetaTools} from "./meta-tools.ts"
import {RegularTools} from "./regular-tools.ts"

export type ConfiguredServerRouteTool = (
	req: mcp.CallToolRequest,
	extra: mcp.RequestExtra,
) => Promise<result.Result<ConfiguredServerRouteToolResult, Error>>

export type ConfiguredServerRouteToolResult = types.CallToolResult & {
	isError?: never
}

export type CallRegularToolHandler = (
	signal: AbortSignal,
	args: unknown,
) => CallRegularToolHandlerResult

export type CallRegularToolHandlerResult =
	result.Result<zodToJsonSchema.JsonSchema7Type, Error> |
	Promise<result.Result<api.Response, Error>> |
	Promise<result.Result<zodToJsonSchema.JsonSchema7Type, Error>> |
	Promise<result.Result<string, Error>>

export interface ConfiguredServerConfig {
	client: api.Client
	resolver: api.Resolver
	uploader: api.Uploader
	dynamic: boolean
	tools: string[]
}

export class ConfiguredServer {
	client: api.Client
	resolver: api.Resolver
	uploader: api.Uploader

	metaTools: MetaTools
	regularTools: RegularTools

	callRegularToolHandlers: Record<string, CallRegularToolHandler | undefined>

	toolsetInfos: mcp.ToolsetInfo[]
	toolInfos: mcp.ToolInfo[]

	routeTool: ConfiguredServerRouteTool

	constructor(config: ConfiguredServerConfig) {
		this.client = config.client
		this.resolver = config.resolver
		this.uploader = config.uploader

		this.metaTools = new MetaTools(this)
		this.regularTools = new RegularTools(this)

		this.callRegularToolHandlers = {
			delete_file: this.regularTools.deleteFile.bind(this.regularTools),
			get_file_info: this.regularTools.getFileInfo.bind(this.regularTools),
			update_file: this.regularTools.updateFile.bind(this.regularTools),
			copy_batch_items: this.regularTools.copyBatchItems.bind(this.regularTools),
			move_batch_items: this.regularTools.moveBatchItems.bind(this.regularTools),
			download_file_as_text: this.regularTools.downloadFileAsText.bind(this.regularTools),
			upload_file: this.regularTools.uploadFile.bind(this.regularTools),
			create_folder: this.regularTools.createFolder.bind(this.regularTools),
			delete_folder: this.regularTools.deleteFolder.bind(this.regularTools),
			get_folder_content: this.regularTools.getFolderContent.bind(this.regularTools),
			get_folder_info: this.regularTools.getFolderInfo.bind(this.regularTools),
			rename_folder: this.regularTools.renameFolder.bind(this.regularTools),
			get_my_folder: this.regularTools.getMyFolder.bind(this.regularTools),
			create_room: this.regularTools.createRoom.bind(this.regularTools),
			get_room_info: this.regularTools.getRoomInfo.bind(this.regularTools),
			update_room: this.regularTools.updateRoom.bind(this.regularTools),
			archive_room: this.regularTools.archiveRoom.bind(this.regularTools),
			set_room_security: this.regularTools.setRoomSecurity.bind(this.regularTools),
			get_room_security_info: this.regularTools.getRoomSecurityInfo.bind(this.regularTools),
			get_rooms_folder: this.regularTools.getRoomsFolder.bind(this.regularTools),
			get_room_types: this.regularTools.getRoomTypes.bind(this.regularTools),
			get_room_access_levels: this.regularTools.getRoomAccessLevels.bind(this.regularTools),
			get_all_people: this.regularTools.getAllPeople.bind(this.regularTools),
		}

		this.toolsetInfos = []
		this.toolInfos = []

		for (let s of toolsetInfos) {
			let o: mcp.ToolsetInfo = {
				name: s.name,
				description: s.description,
				tools: [],
			}

			for (let n of config.tools) {
				for (let t of s.tools) {
					if (t.name === n) {
						o.tools.push(t)
						break
					}
				}
			}

			if (o.tools.length !== 0) {
				this.toolsetInfos.push(o)
			}
		}

		if (config.dynamic) {
			this.toolInfos = [...metaToolInfos]
			this.routeTool = this.routeMetaTool.bind(this)
		} else {
			for (let s of this.toolsetInfos) {
				this.toolInfos.push(...s.tools)
			}
			this.routeTool = this.routeRegularTool.bind(this)
		}
	}

	listTools(): types.ListToolsResult {
		return {
			tools: this.toolInfos,
		}
	}

	async callTool(
		req: mcp.CallToolRequest,
		extra: mcp.RequestExtra,
	): Promise<types.CallToolResult> {
		let pr = await this.routeTool(req, extra)

		if (pr.err) {
			return {
				content: [
					{
						type: "text",
						text: errors.format(pr.err),
					},
				],
				isError: true,
			}
		}

		return pr.v
	}

	async routeMetaTool(
		req: mcp.CallToolRequest,
		extra: mcp.RequestExtra,
	): Promise<result.Result<ConfiguredServerRouteToolResult, Error>> {
		let mr: result.Result<
			mcp.Summary[] |
			mcp.ToolInputSchema |
			mcp.ToolOutputSchema,
			Error
		> | undefined

		let rr: result.Result<
			ConfiguredServerRouteToolResult,
			Error
		> | undefined

		try {
			switch (req.params.name) {
			case "list_toolsets":
				mr = this.metaTools.listToolsets()
				break
			case "list_tools":
				mr = this.metaTools.listTools(req)
				break
			case "get_tool_input_schema":
				mr = this.metaTools.getToolInputSchema(req)
				break
			case "get_tool_output_schema":
				mr = this.metaTools.getToolOutputSchema(req)
				break
			case "call_tool":
				rr = await this.metaTools.callTool(req, extra)
				break
			default:
				mr = result.error(new Error(`Tool ${req.params.name} not found.`))
				break
			}
		} catch (err) {
			if (err instanceof Error) {
				mr = result.error(err)
			} else {
				mr = result.error(new Error("Unknown error.", {cause: err}))
			}
		}

		if (mr) {
			if (mr.err) {
				return result.error(mr.err)
			}

			let s = result.safeSync(JSON.stringify, mr.v, undefined, 2)
			if (s.err) {
				return result.error(new Error("Stringifying value", {cause: s.err}))
			}

			let r: ConfiguredServerRouteToolResult = {
				content: [
					{
						type: "text",
						text: s.v,
					},
				],
			}

			return result.ok(r)
		}

		if (rr) {
			return rr
		}

		return result.error(new Error("Unknown result type"))
	}

	async routeRegularTool(
		req: mcp.CallToolRequest,
		extra: mcp.RequestExtra,
	): Promise<result.Result<ConfiguredServerRouteToolResult, Error>> {
		let f = false

		for (let s of this.toolsetInfos) {
			for (let t of s.tools) {
				if (t.name === req.params.name) {
					f = true
					break
				}
			}

			if (f) {
				break
			}
		}

		if (!f) {
			return result.error(new Error(`Tool ${req.params.name} not found`))
		}

		let cr: Awaited<CallRegularToolHandlerResult> | undefined

		try {
			let h = this.callRegularToolHandlers[req.params.name]
			if (h) {
				cr = await h(extra.signal, req.params.arguments)
			} else {
				cr = result.error(new Error(`Tool ${req.params.name} not found.`))
			}
		} catch (err) {
			if (err instanceof Error) {
				cr = result.error(err)
			} else {
				cr = result.error(new Error("Unknown error.", {cause: err}))
			}
		}

		if (cr.err) {
			return result.error(cr.err)
		}

		if (cr.v instanceof api.Response) {
			let h = cr.v.response.headers.get("Content-Type")
			if (h === null) {
				return result.error(new Error("Content-Type header is missing"))
			}

			if (h.startsWith("application/json")) {
				let j = await result.safeAsync(cr.v.response.json.bind(cr.v.response))
				if (j.err) {
					return result.error(new Error("Parsing json response", {cause: j.err}))
				}

				let s = result.safeSync(JSON.stringify, j.v, undefined, 2)
				if (s.err) {
					return result.error(new Error("Stringifying json value", {cause: s.err}))
				}

				let r: ConfiguredServerRouteToolResult = {
					content: [
						{
							type: "text",
							text: s.v,
						},
					],
				}

				let f = false

				for (let s of this.toolsetInfos) {
					for (let t of s.tools) {
						if (t.name === req.params.name) {
							f = true

							if (t.outputSchema) {
								r.structuredContent = j.v
							}

							break
						}
					}

					if (f) {
						break
					}
				}

				return result.ok(r)
			}

			if (h.startsWith("text/")) {
				let t = await result.safeAsync(cr.v.response.text.bind(cr.v.response))
				if (t.err) {
					return result.error(new Error("Parsing text response", {cause: t.err}))
				}

				let r: ConfiguredServerRouteToolResult = {
					content: [
						{
							type: "text",
							text: t.v,
						},
					],
				}

				return result.ok(r)
			}

			return result.error(new Error(`Content-Type ${h} is not supported`))
		}

		if (typeof cr.v === "object") {
			let s = result.safeSync(JSON.stringify, cr.v, undefined, 2)
			if (s.err) {
				return result.error(new Error("Stringifying object value", {cause: s.err}))
			}

			let r: ConfiguredServerRouteToolResult = {
				content: [
					{
						type: "text",
						text: s.v,
					},
				],
			}

			let f = false

			for (let s of this.toolsetInfos) {
				for (let t of s.tools) {
					if (t.name === req.params.name) {
						f = true

						if (t.outputSchema) {
							r.structuredContent = cr.v
						}

						break
					}
				}

				if (f) {
					break
				}
			}

			return result.ok(r)
		}

		if (typeof cr.v === "string") {
			let r: ConfiguredServerRouteToolResult = {
				content: [
					{
						type: "text",
						text: cr.v,
					},
				],
			}

			return result.ok(r)
		}

		return result.error(new Error("Unknown result type"))
	}
}

export function configuredServer(
	config: ConfiguredServerConfig,
): mcp.RequestDefinition[] {
	let s = new ConfiguredServer(config)

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
