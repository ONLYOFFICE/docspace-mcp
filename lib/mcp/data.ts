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

import * as mcp from "../util/mcp.ts"
import {
	CallToolInputSchema,
	GetToolInputSchemaInputSchema,
	GetToolOutputSchemaInputSchema,
	ListToolsInputSchema,
} from "./meta-tools.ts"
import {
	ArchiveRoomInputSchema,
	CopyBatchItemsInputSchema,
	CreateFolderInputSchema,
	CreateFolderOutputSchema,
	CreateRoomInputSchema,
	CreateRoomOutputSchema,
	DeleteFileInputSchema,
	DeleteFolderInputSchema,
	DownloadFileAsTextInputSchema,
	GetAllPeopleInputSchema,
	GetAllPeopleOutputSchema,
	GetFileInfoInputSchema,
	GetFileInfoOutputSchema,
	GetFolderContentInputSchema,
	GetFolderContentOutputSchema,
	GetFolderInfoInputSchema,
	GetFolderInfoOutputSchema,
	GetMyFolderInputSchema,
	GetMyFolderOutputSchema,
	GetRoomAccessLevelsSchema,
	GetRoomInfoInputSchema,
	GetRoomInfoOutputSchema,
	GetRoomSecurityInfoInputSchema,
	GetRoomSecurityInfoOutputSchema,
	GetRoomsFolderInputSchema,
	GetRoomsFolderOutputSchema,
	MoveBatchItemsInputSchema,
	RenameFolderInputSchema,
	RenameFolderOutputSchema,
	SetRoomSecurityInputSchema,
	SetRoomSecurityOutputSchema,
	UpdateFileInputSchema,
	UpdateFileOutputSchema,
	UpdateRoomInputSchema,
	UpdateRoomOutputSchema,
	UploadFileInputSchema,
} from "./regular-tools.ts"

export const metaToolInfos = mcp.toToolInfos([
	{
		name: "list_toolsets",
		description: "This is a meta-tool for listing available toolsets. Toolset is a set of available tools.",
	},
	{
		name: "list_tools",
		description: "This is a meta-tool for listing available tools of a specific toolset. The list of available toolsets can be obtained using the list_toolsets meta-tool.",
		inputSchema: ListToolsInputSchema,
	},
	{
		name: "get_tool_input_schema",
		description: "This is a meta-tool for getting an input schema for a specific tool. The list of available tools can be obtained using the list_tools meta-tool.",
		inputSchema: GetToolInputSchemaInputSchema,
	},
	{
		name: "get_tool_output_schema",
		description: "This is a meta-tool for getting an output schema for a specific tool. The list of available tools can be obtained using the list_tools meta-tool.",
		inputSchema: GetToolOutputSchemaInputSchema,
	},
	{
		name: "call_tool",
		description: "This is a meta-tool for calling a tool. The list of available tools can be obtained using the list_tools meta-tool. The input schema can be obtained using the get_tool_input_schema meta-tool.",
		inputSchema: CallToolInputSchema,
	},
])

export const toolsetInfos = mcp.toToolsetInfos([
	{
		name: "files",
		description: "Operations for working with files.",
		tools: [
			{
				name: "delete_file",
				description: "Delete a file.",
				inputSchema: DeleteFileInputSchema,
			},
			{
				name: "get_file_info",
				description: "Get file information.",
				inputSchema: GetFileInfoInputSchema,
				outputSchema: GetFileInfoOutputSchema,
			},
			{
				name: "update_file",
				description: "Update a file.",
				inputSchema: UpdateFileInputSchema,
				outputSchema: UpdateFileOutputSchema,
			},
			{
				name: "copy_batch_items",
				description: "Copy to a folder.",
				inputSchema: CopyBatchItemsInputSchema,
			},
			{
				name: "move_batch_items",
				description: "Move to a folder.",
				inputSchema: MoveBatchItemsInputSchema,
			},
			{
				name: "download_file_as_text",
				description: "Download a file as text.",
				inputSchema: DownloadFileAsTextInputSchema,
			},
			{
				name: "upload_file",
				description: "Upload a file.",
				inputSchema: UploadFileInputSchema,
			},
		],
	},
	{
		name: "folders",
		description: "Operations for working with folders.",
		tools: [
			{
				name: "create_folder",
				description: "Create a folder.",
				inputSchema: CreateFolderInputSchema,
				outputSchema: CreateFolderOutputSchema,
			},
			{
				name: "delete_folder",
				description: "Delete a folder.",
				inputSchema: DeleteFolderInputSchema,
			},
			{
				name: "get_folder_content",
				description: "Get content of a folder.",
				inputSchema: GetFolderContentInputSchema,
				outputSchema: GetFolderContentOutputSchema,
			},
			{
				name: "get_folder_info",
				description: "Get folder information.",
				inputSchema: GetFolderInfoInputSchema,
				outputSchema: GetFolderInfoOutputSchema,
			},
			{
				name: "rename_folder",
				description: "Rename a folder.",
				inputSchema: RenameFolderInputSchema,
				outputSchema: RenameFolderOutputSchema,
			},
			{
				name: "get_my_folder",
				description: "Get the 'My Documents' folder.",
				inputSchema: GetMyFolderInputSchema,
				outputSchema: GetMyFolderOutputSchema,
			},
		],
	},
	{
		name: "rooms",
		description: "Operations for working with rooms.",
		tools: [
			{
				name: "create_room",
				description: "Create a room.",
				inputSchema: CreateRoomInputSchema,
				outputSchema: CreateRoomOutputSchema,
			},
			{
				name: "get_room_info",
				description: "Get room information.",
				inputSchema: GetRoomInfoInputSchema,
				outputSchema: GetRoomInfoOutputSchema,
			},
			{
				name: "update_room",
				description: "Update a room.",
				inputSchema: UpdateRoomInputSchema,
				outputSchema: UpdateRoomOutputSchema,
			},
			{
				name: "archive_room",
				description: "Archive a room.",
				inputSchema: ArchiveRoomInputSchema,
			},
			{
				name: "set_room_security",
				description: "Invite or remove users from a room.",
				inputSchema: SetRoomSecurityInputSchema,
				outputSchema: SetRoomSecurityOutputSchema,
			},
			{
				name: "get_room_security_info",
				description: "Get a list of users with their access levels to a room.",
				inputSchema: GetRoomSecurityInfoInputSchema,
				outputSchema: GetRoomSecurityInfoOutputSchema,
			},
			{
				name: "get_rooms_folder",
				description: "Get the 'Rooms' folder.",
				inputSchema: GetRoomsFolderInputSchema,
				outputSchema: GetRoomsFolderOutputSchema,
			},
			{
				name: "get_room_types",
				description: "Get a list of available room types.",
			},
			{
				name: "get_room_access_levels",
				description: "Get a list of available room invitation access levels.",
				inputSchema: GetRoomAccessLevelsSchema,
			},
		],
	},
	{
		name: "people",
		description: "Operations for working with users.",
		tools: [
			{
				name: "get_all_people",
				description: "Get all people.",
				inputSchema: GetAllPeopleInputSchema,
				outputSchema: GetAllPeopleOutputSchema,
			},
		],
	},
])
