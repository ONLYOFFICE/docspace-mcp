/**
 * @module
 * @mergeModuleWith mcp
 */

import path from "node:path"
import type * as types from "@modelcontextprotocol/sdk/types.js"
import * as z from "zod"
import type * as apiCore from "../api/core.ts"
import * as core from "../api/core.ts"
import type * as apiExtra from "../api/extra.ts"
import * as officeApi from "../office-api.ts"
import * as errors from "../util/errors.ts"
import type * as mcp from "../util/mcp.ts"
import * as r from "../util/result.ts"
import {unionToEnum} from "../util/zod.ts"

type CallToolHandler = (req: Parameters<mcp.CallToolRequestHandler>[0]) => ReturnType<mcp.CallToolRequestHandler>

const CallToolInputSchema = z.object({
  tool: z.string().describe("The name of the tool to call."),
  input: z.looseObject({}).optional().describe("The value that corresponds to the input schema of the tool."),
})

const CallToolInputJsonSchema = z.toJSONSchema(CallToolInputSchema)

const GetToolInputSchemaInputSchema = z.object({
  tool: z.string().describe("The name of the tool to get input schema for."),
})

const GetToolInputSchemaInputJsonSchema = z.toJSONSchema(GetToolInputSchemaInputSchema)

const GetToolOutputSchemaInputSchema = z.object({
  tool: z.string().describe("The name of the tool to get output schema for."),
})

const GetToolOutputSchemaInputJsonSchema = z.toJSONSchema(GetToolOutputSchemaInputSchema)

const ListToolsInputSchema = z.object({
  toolset: z.string().describe("The name of the toolset to list tools from."),
})

const ListToolsInputJsonSchema = z.toJSONSchema(ListToolsInputSchema)

const RoomInvitationAccessSchema = z.union([
  z.literal(0).describe("None. No access to the room."),
  z.literal(2).describe("Viewer. File viewing."),
  z.literal(5).describe("Reviewer. Operations with existing files: viewing, reviewing, commenting."),
  z.literal(6).describe("Commenter. Operations with existing files: viewing, commenting."),
  z.literal(7).describe("Form filler. Form fillers can fill out forms and view only their completed/started forms within the Complete and In Process folders."),
  z.literal(9).describe("Room manager (Paid). Room managers can manage the assigned rooms, invite new users and assign roles below their level."),
  z.literal(10).describe("Editor. Operations with existing files: viewing, editing, form filling, reviewing, commenting."),
  z.literal(11).describe("Content creator. Content creators can create and edit files in the room, but can't manage users, or access settings."),
])

const FormFillingRoomInvitationAccessSchema = z.union([
  RoomInvitationAccessSchema._zod.def.options[4],
  RoomInvitationAccessSchema._zod.def.options[5],
  RoomInvitationAccessSchema._zod.def.options[7],
])

const CollaborationRoomInvitationAccessSchema = z.union([
  RoomInvitationAccessSchema._zod.def.options[1],
  RoomInvitationAccessSchema._zod.def.options[5],
  RoomInvitationAccessSchema._zod.def.options[6],
  RoomInvitationAccessSchema._zod.def.options[7],
])

const CustomRoomInvitationAccessSchema = z.union([
  RoomInvitationAccessSchema._zod.def.options[1],
  RoomInvitationAccessSchema._zod.def.options[2],
  RoomInvitationAccessSchema._zod.def.options[3],
  RoomInvitationAccessSchema._zod.def.options[5],
  RoomInvitationAccessSchema._zod.def.options[6],
  RoomInvitationAccessSchema._zod.def.options[7],
])

const PublicRoomInvitationAccessSchema = z.union([
  RoomInvitationAccessSchema._zod.def.options[5],
  RoomInvitationAccessSchema._zod.def.options[7],
])

const VirtualDataRoomInvitationAccessSchema = z.union([
  RoomInvitationAccessSchema._zod.def.options[1],
  RoomInvitationAccessSchema._zod.def.options[4],
  RoomInvitationAccessSchema._zod.def.options[5],
  RoomInvitationAccessSchema._zod.def.options[6],
  RoomInvitationAccessSchema._zod.def.options[7],
])

const ArchiveRoomInputSchema = z.object({
  roomId: z.number().describe("The ID of the room to archive."),
})

const ArchiveRoomInputJsonSchema = z.toJSONSchema(ArchiveRoomInputSchema)

const CopyBatchItemsInputSchema = z.object({
  folderIds: z.
  // The Windsurf Editor is experiencing an issue parsing the following type.
  // array(z.union([z.number(), z.string()])).
    array(z.unknown()).
    optional().
    describe("The IDs of the folders to copy."),
  fileIds: z.
  // The Windsurf Editor is experiencing an issue parsing the following type.
  // array(z.union([z.number(), z.string()])).
    array(z.unknown()).
    optional().
    describe("The IDs of the files to copy."),
  destFolderId: z.
  // The Windsurf Editor is experiencing an issue parsing the following type.
  // union([z.number(), z.string()]).
    unknown().
    optional().
    describe("The ID of the destination folder to copy the items to."),
})

const CopyBatchItemsInputJsonSchema = z.toJSONSchema(CopyBatchItemsInputSchema)

const CreateFolderInputSchema = z.object({
  parentId: z.number().describe("The ID of the room or folder to create the folder in."),
  title: z.string().describe("The title of the folder to create."),
  filters: core.CreateFolderFiltersSchema.describe("The filters to apply to the folder creation. Use them to reduce the size of the response."),
})

const CreateFolderInputJsonSchema = z.toJSONSchema(CreateFolderInputSchema)

const CreateFolderOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.FolderDtoSchema.describe("The created folder information."),
})

const CreateFolderOutputJsonSchema = z.toJSONSchema(CreateFolderOutputSchema)

const CreateRoomInputSchema = z.object({
  title: z.string().describe("The title of the room to create."),
  roomType: unionToEnum(core.RoomTypeSchema, "The type of the room to create.").optional().default(6),
  filters: core.CreateRoomFiltersSchema.describe("The filters to apply to the room creation."),
})

const CreateRoomInputJsonSchema = z.toJSONSchema(CreateRoomInputSchema)

const CreateRoomOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.FolderContentDtoSchema.describe("The contents of the created room."),
})

const CreateRoomOutputJsonSchema = z.toJSONSchema(CreateRoomOutputSchema)

const DeleteFileInputSchema = z.object({
  fileId: z.number().describe("The ID of the file to delete."),
})

const DeleteFileInputJsonSchema = z.toJSONSchema(DeleteFileInputSchema)

const DeleteFolderInputSchema = z.object({
  folderId: z.number().describe("The ID of the folder to delete."),
})

const DeleteFolderInputJsonSchema = z.toJSONSchema(DeleteFolderInputSchema)

const DownloadFileAsTextInputSchema = z.object({
  fileId: z.number().describe("The ID of the file to download as text."),
})

const DownloadFileAsTextInputJsonSchema = z.toJSONSchema(DownloadFileAsTextInputSchema)

const GetAllPeopleInputSchema = z.object({
  filters: core.GetFullByFilterFiltersSchema.describe("The filters to apply to the list of people. Use them to reduce the size of the response."),
})

const GetAllPeopleInputJsonSchema = z.toJSONSchema(GetAllPeopleInputSchema)

const GetAllPeopleOutputSchema = core.SuccessApiResponseSchema.extend({
  response: z.array(core.EmployeeDtoSchema),
})

const GetAllPeopleOutputJsonSchema = z.toJSONSchema(GetAllPeopleOutputSchema)

const GetFileInfoInputSchema = z.object({
  fileId: z.number().describe("The ID of the file to get info for."),
  filters: core.GetFileInfoFiltersSchema.describe("The filters to apply to the file info. Use them to reduce the size of the response."),
})

const GetFileInfoInputJsonSchema = z.toJSONSchema(GetFileInfoInputSchema)

const GetFileInfoOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.FileDtoSchema.describe("The file information."),
})

const GetFileInfoOutputJsonSchema = z.toJSONSchema(GetFileInfoOutputSchema)

const GetFolderContentInputSchema = z.object({
  folderId: z.number().describe("The ID of the folder to get."),
  filters: core.GetFolderFiltersSchema.describe("The filters to apply to the contents of the folder. Use them to reduce the size of the response."),
})

const GetFolderContentInputJsonSchema = z.toJSONSchema(GetFolderContentInputSchema)

const GetFolderContentOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.FolderContentDtoSchema.describe("The contents of the folder."),
})

const GetFolderContentOutputJsonSchema = z.toJSONSchema(GetFolderContentOutputSchema)

const GetFolderInfoInputSchema = z.object({
  folderId: z.number().describe("The ID of the folder to get info for."),
  filters: core.GetFolderInfoFiltersSchema.describe("The filters to apply to the folder info. Use them to reduce the size of the response."),
})

const GetFolderInfoInputJsonSchema = z.toJSONSchema(GetFolderInfoInputSchema)

const GetFolderInfoOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.FolderDtoSchema.describe("The folder information."),
})

const GetFolderInfoOutputJsonSchema = z.toJSONSchema(GetFolderInfoOutputSchema)

const GetMyFolderInputSchema = z.object({
  filters: core.GetMyFolderFiltersSchema.describe("The filters to apply to the My Documents folder. Use them to reduce the size of the response."),
})

const GetMyFolderInputJsonSchema = z.toJSONSchema(GetMyFolderInputSchema)

const GetMyFolderOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.FolderContentDtoSchema.describe("The contents of the My Documents folder."),
})

const GetMyFolderOutputJsonSchema = z.toJSONSchema(GetMyFolderOutputSchema)

const GetOfficeApiReferenceInputSchema = z.object({
  editor: z.enum(officeApi.editors).describe("The editor whose API to look up: document, spreadsheet, presentation, form for the form fields of a document or a PDF form, or pdf."),
  query: z.string().optional().describe("Words to look for in the names and descriptions of classes, methods and enumerations, such as \"watermark\" or \"table border\". Use it to find out what to get with class and method."),
  class: z.string().optional().describe("The name of a class or an enumeration to get, such as ApiParagraph or Drawing. Without method, returns the description of the class and the list of its methods."),
  method: z.string().optional().describe("The name of a method of the class to get, such as AddText. Returns its syntax, parameters, return value and an example."),
})

const GetOfficeApiReferenceInputJsonSchema = z.toJSONSchema(GetOfficeApiReferenceInputSchema)

const GetRoomAccessLevelsInputSchema = z.object({
  roomId: z.number().describe("The ID of the room to get the invitation access for."),
})

const GetRoomAccessLevelsInputJsonSchema = z.toJSONSchema(GetRoomAccessLevelsInputSchema)

const GetRoomInfoInputSchema = z.object({
  roomId: z.number().describe("The ID of the room to get info for."),
  filters: core.GetRoomInfoFiltersSchema.describe("The filters to apply to the room info."),
})

const GetRoomInfoInputJsonSchema = z.toJSONSchema(GetRoomInfoInputSchema)

const GetRoomInfoOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.FolderDtoSchema.describe("The room information."),
})

const GetRoomInfoOutputJsonSchema = z.toJSONSchema(GetRoomInfoOutputSchema)

const GetRoomSecurityInfoInputSchema = z.object({
  roomId: z.number().describe("The ID of the room to get a list of users with their access level for."),
  filters: core.GetRoomSecurityFiltersSchema.describe("The filters to apply to the room security info."),
})

const GetRoomSecurityInfoInputJsonSchema = z.toJSONSchema(GetRoomSecurityInfoInputSchema)

const GetRoomSecurityInfoOutputSchema = core.SuccessApiResponseSchema.extend({
  response: z.array(core.FileShareDtoSchema).describe("The room security information."),
})

const GetRoomSecurityInfoOutputJsonSchema = z.toJSONSchema(GetRoomSecurityInfoOutputSchema)

const GetRoomsFolderInputSchema = z.object({
  filters: core.GetRoomsFolderFiltersSchema.describe("The filters to apply to the rooms folder."),
})

const GetRoomsFolderInputJsonSchema = z.toJSONSchema(GetRoomsFolderInputSchema)

const GetRoomsFolderOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.FolderContentDtoSchema.describe("The contents of the rooms folder."),
})

const GetRoomsFolderOutputJsonSchema = z.toJSONSchema(GetRoomsFolderOutputSchema)

const MoveBatchItemsInputSchema = z.object({
  folderIds: z.
  // The Windsurf Editor is experiencing an issue parsing the following type.
  // array(z.union([z.number(), z.string()])).
    array(z.unknown()).
    optional().
    describe("The IDs of the folders to move items to."),
  fileIds: z.
  // The Windsurf Editor is experiencing an issue parsing the following type.
  // array(z.union([z.number(), z.string()])).
    array(z.unknown()).
    optional().
    describe("The IDs of the files to move."),
  destFolderId: z.
  // The Windsurf Editor is experiencing an issue parsing the following type.
  // union([z.number(), z.string()]).
    unknown().
    optional().
    describe("The ID of the destination folder to move the items to."),
})

const MoveBatchItemsInputJsonSchema = z.toJSONSchema(MoveBatchItemsInputSchema)

const RenameFolderInputSchema = z.object({
  folderId: z.number().describe("The ID of the folder to rename."),
  title: z.string().describe("The new title of the folder to set."),
  filters: core.RenameFolderFiltersSchema.describe("The filters to apply to the folder renaming. Use them to reduce the size of the response."),
})

const RenameFolderInputJsonSchema = z.toJSONSchema(RenameFolderInputSchema)

const RenameFolderOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.FolderDtoSchema.describe("The renamed folder information."),
})

const RenameFolderOutputJsonSchema = z.toJSONSchema(RenameFolderOutputSchema)

// The saved files come from the operation status, which the shared poller
// requests for all operations at once, so the fields are picked here instead
// of being passed to the server.
const RunBuilderScriptFileFieldSchema = z.union([
  ...core.FileDtoFieldSchema.options,
  z.literal("version").describe("The file version."),
  z.literal("webUrl").describe("The Web URL link to the file."),
  z.literal("viewUrl").describe("The URL link to download the file."),
  z.literal("contentLength").describe("The content length of the file."),
])

const RunBuilderScriptInputSchema = z.object({
  script: z.string().describe([
    "The ONLYOFFICE Document Builder script to run, written in JavaScript against the Office JavaScript API (Api.GetDocument(), Api.CreateParagraph() and so on).",
    "Start it with builder.CreateFile(\"docx\") to make a new document (or \"xlsx\", \"pptx\", \"pdf\"), or with builder.OpenFile(\"<file ID>\") to open a portal file by its ID; addresses and http or https URLs are refused.",
    "Save each result with builder.SaveFile(\"<format>\", \"<name with extension>\") and finish with builder.CloseFile().",
    "Every builder.* call has to be on its own line; a script that puts them on one line saves nothing.",
    "OpenFile and SaveFile may be called at most 20 times each.",
    "Take the signatures of the methods it calls from the get_office_api_reference tool, not from memory: parameters change between versions, and an error raised by the script is reported without details.",
  ].join(" ")),
  folderId: z.number().optional().describe("The ID of the folder to save the produced files that are not listed in outputs to. Required when the script creates a file instead of opening one; otherwise the files are saved to the folder of the opened file."),
  outputs: z.
    record(
      z.string(),
      z.object({
        fileId: z.number().optional().describe("The ID of the file to store the result in as a new version. The result has to be in the format of that file. Do not combine with folderId and title."),
        folderId: z.number().optional().describe("The ID of the folder to save the result to as a new file."),
        title: z.string().optional().describe("The title of the new file, when it has to differ from the name passed to SaveFile. Only with folderId."),
      }),
    ).
    optional().
    describe("Destinations of the produced files, keyed by the name passed to builder.SaveFile. Each entry names exactly one of fileId and folderId."),
  argument: z.
    record(z.string(), z.unknown()).
    optional().
    describe("Values the script reads through the global Argument object, such as Argument.title. Must not contain http or https URLs."),
  filters: z.
    object({
      fields: z.array(unionToEnum(RunBuilderScriptFileFieldSchema, "The fields of the saved files to include in the response.")),
    }).
    optional().
    default({fields: ["id", "title", "version", "webUrl", "folderId"]}).
    describe("The filters to apply to the saved files. Without them, each file has only its id, title, version, webUrl and folderId."),
})

const RunBuilderScriptInputJsonSchema = z.toJSONSchema(RunBuilderScriptInputSchema)

const RunBuilderScriptOutputSchema = z.object({
  files: z.
    array(
      core.FileDtoSchema.extend({
        version: z.number().optional().describe("The file version."),
        webUrl: z.string().optional().describe("The Web URL link to the file."),
        viewUrl: z.string().optional().describe("The URL link to download the file."),
        contentLength: z.string().optional().describe("The content length of the file."),
      }),
    ).
    describe("The files saved by the script, with only the fields asked for in filters."),
})

const RunBuilderScriptOutputJsonSchema = z.toJSONSchema(RunBuilderScriptOutputSchema)

const SetRoomSecurityInputSchema = z.object({
  roomId: z.
    number().
    describe("The ID of the room to invite or remove users from."),
  invitations: z.
    array(
      z.
        object({
          id: z.
            string().
            optional().
            describe("The ID of the user to invite or remove. Mutually exclusive with User Email."),
          email: z.
            string().
            optional().
            describe("The email of the user to invite or remove. Mutually exclusive with User ID."),
          access: unionToEnum(RoomInvitationAccessSchema, "The access level to grant to the user. May vary depending on the type of room.").
            optional(),
        }).
        describe("The invitation or removal of a user. Must contain either User ID or User Email.").
        refine(
          (o) => o.id !== undefined || o.email !== undefined,
          {
            message: "Either User ID or User Email must be provided.",
            path: ["id", "email"],
          },
        ),
    ).
    describe("The invitations or removals to perform."),
  notify: z.
    boolean().
    optional().
    describe("Whether to notify the user."),
  message: z.
    string().
    optional().
    describe("The message to use for the invitation."),
  culture: z.
    string().
    optional().
    describe("The languages to use for the invitation."),
  filters: core.SetRoomSecurityFiltersSchema.describe("The filters to apply to the room security info."),
})

const SetRoomSecurityInputJsonSchema = z.toJSONSchema(SetRoomSecurityInputSchema)

const SetRoomSecurityOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.RoomSecurityDtoSchema.describe("The room security information after the operation."),
})

const SetRoomSecurityOutputJsonSchema = z.toJSONSchema(SetRoomSecurityOutputSchema)

const UpdateFileInputSchema = z.object({
  fileId: z.number().describe("The ID of the file to update."),
  title: z.string().describe("The new title of the file to set."),
})

const UpdateFileInputJsonSchema = z.toJSONSchema(UpdateFileInputSchema)

const UpdateFileOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.FileDtoSchema.describe("The updated file information."),
})

const UpdateFileOutputJsonSchema = z.toJSONSchema(UpdateFileOutputSchema)

const UpdateRoomInputSchema = z.object({
  roomId: z.number().describe("The ID of the room to update."),
  title: z.string().optional().describe("The new title of the room to set."),
  filters: core.UpdateRoomFiltersSchema.describe("The filters to apply to the room update."),
})

const UpdateRoomInputJsonSchema = z.toJSONSchema(UpdateRoomInputSchema)

const UpdateRoomOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.FolderDtoSchema.describe("The updated room information."),
})

const UpdateRoomOutputJsonSchema = z.toJSONSchema(UpdateRoomOutputSchema)

const UploadFileInputSchema = z.object({
  parentId: z.number().describe("The ID of the room or folder to upload the file to."),
  filename: z.string().describe("The file name with an extension to upload."),
  content: z.string().describe("The content of the file to upload."),
})

const UploadFileInputJsonSchema = z.toJSONSchema(UploadFileInputSchema)

// todo: remove export
export const metaTools = [
  {
    name: "list_toolsets",
    description: "This is a meta tool for listing available toolsets. Toolset is a set of available tools.",
    inputSchema: z.toJSONSchema(z.object({})),
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "list_tools",
    description: "This is a meta tool for listing available tools of a specific toolset. The list of available toolsets can be obtained using the list_toolsets meta tool.",
    inputSchema: ListToolsInputJsonSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "get_tool_input_schema",
    description: "This is a meta tool for getting an input schema for a specific tool. The list of available tools can be obtained using the list_tools meta tool.",
    inputSchema: GetToolInputSchemaInputJsonSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "get_tool_output_schema",
    description: "This is a meta tool for getting an output schema for a specific tool. The list of available tools can be obtained using the list_tools meta tool.",
    inputSchema: GetToolOutputSchemaInputJsonSchema,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "call_tool",
    description: "This is a meta tool for calling a tool. The list of available tools can be obtained using the list_tools meta tool. The input schema can be obtained using the get_tool_input_schema meta tool.",
    inputSchema: CallToolInputJsonSchema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      openWorldHint: true,
    },
  },
] as mcp.Tool[]

// todo: remove export
export const regularToolsets = [
  {
    name: "files",
    description: "Operations for working with files.",
    tools: [
      {
        name: "delete_file",
        description: "Delete a file.",
        inputSchema: DeleteFileInputJsonSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: true,
          openWorldHint: false,
        },
      },
      {
        name: "get_file_info",
        description: "Get file information.",
        inputSchema: GetFileInfoInputJsonSchema,
        outputSchema: GetFileInfoOutputJsonSchema,
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "update_file",
        description: "Update a file.",
        inputSchema: UpdateFileInputJsonSchema,
        outputSchema: UpdateFileOutputJsonSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: true,
          openWorldHint: false,
        },
      },
      {
        name: "copy_batch_items",
        description: "Copy to a folder.",
        inputSchema: CopyBatchItemsInputJsonSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "move_batch_items",
        description: "Move to a folder.",
        inputSchema: MoveBatchItemsInputJsonSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "download_file_as_text",
        description: "Download a file as text.",
        inputSchema: DownloadFileAsTextInputJsonSchema,
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "upload_file",
        description: "Upload a file.",
        inputSchema: UploadFileInputJsonSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "get_office_api_reference",
        description: "Look up the Office JavaScript API that run_builder_script scripts are written against. Use it before every run_builder_script call to check the methods the script uses, since the API changes between versions and remembered signatures may be outdated. Without class and query, returns an overview of the editor API with the list of its classes and enumerations; with query, finds classes, methods and enumerations; with class, returns the methods of a class or the values of an enumeration; with class and method, returns the syntax, parameters and an example of a method. The reference is read from api.onlyoffice.com.",
        inputSchema: GetOfficeApiReferenceInputJsonSchema,
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: true,
        },
      },
      {
        name: "run_builder_script",
        description: "Run an ONLYOFFICE Document Builder script to create or edit documents, spreadsheets, presentations or PDFs, and wait for it to finish. The Office JavaScript API changes between versions (since 9.4.0, for example, Api.CreateTable takes rows before columns), so do not write the script from memory: look up every class and method it uses with the get_office_api_reference tool first. Returns the saved files in the files field; a file may get a different title than the name passed to builder.SaveFile when the folder already has a file with that name.",
        inputSchema: RunBuilderScriptInputJsonSchema,
        outputSchema: RunBuilderScriptOutputJsonSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: true,
          openWorldHint: false,
        },
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
        inputSchema: CreateFolderInputJsonSchema,
        outputSchema: CreateFolderOutputJsonSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: true,
          openWorldHint: false,
        },
      },
      {
        name: "delete_folder",
        description: "Delete a folder.",
        inputSchema: DeleteFolderInputJsonSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: true,
          openWorldHint: false,
        },
      },
      {
        name: "get_folder_content",
        description: "Get content of a folder.",
        inputSchema: GetFolderContentInputJsonSchema,
        outputSchema: GetFolderContentOutputJsonSchema,
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "get_folder_info",
        description: "Get folder information.",
        inputSchema: GetFolderInfoInputJsonSchema,
        outputSchema: GetFolderInfoOutputJsonSchema,
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "rename_folder",
        description: "Rename a folder.",
        inputSchema: RenameFolderInputJsonSchema,
        outputSchema: RenameFolderOutputJsonSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: true,
          openWorldHint: false,
        },
      },
      {
        name: "get_my_folder",
        description: "Get the 'My Documents' folder.",
        inputSchema: GetMyFolderInputJsonSchema,
        outputSchema: GetMyFolderOutputJsonSchema,
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
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
        inputSchema: CreateRoomInputJsonSchema,
        outputSchema: CreateRoomOutputJsonSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: true,
          openWorldHint: false,
        },
      },
      {
        name: "get_room_info",
        description: "Get room information.",
        inputSchema: GetRoomInfoInputJsonSchema,
        outputSchema: GetRoomInfoOutputJsonSchema,
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "update_room",
        description: "Update a room.",
        inputSchema: UpdateRoomInputJsonSchema,
        outputSchema: UpdateRoomOutputJsonSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: true,
          openWorldHint: false,
        },
      },
      {
        name: "archive_room",
        description: "Archive a room.",
        inputSchema: ArchiveRoomInputJsonSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "set_room_security",
        description: "Invite or remove users from a room.",
        inputSchema: SetRoomSecurityInputJsonSchema,
        outputSchema: SetRoomSecurityOutputJsonSchema,
        annotations: {
          readOnlyHint: false,
          destructiveHint: true,
          openWorldHint: true,
        },
      },
      {
        name: "get_room_security_info",
        description: "Get a list of users with their access levels to a room.",
        inputSchema: GetRoomSecurityInfoInputJsonSchema,
        outputSchema: GetRoomSecurityInfoOutputJsonSchema,
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "get_rooms_folder",
        description: "Get the 'Rooms' folder.",
        inputSchema: GetRoomsFolderInputJsonSchema,
        outputSchema: GetRoomsFolderOutputJsonSchema,
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "get_room_types",
        description: "Get a list of available room types.",
        inputSchema: z.toJSONSchema(z.object({})),
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "get_room_access_levels",
        description: "Get a list of available room invitation access levels.",
        inputSchema: GetRoomAccessLevelsInputJsonSchema,
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
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
        inputSchema: GetAllPeopleInputJsonSchema,
        outputSchema: GetAllPeopleOutputJsonSchema,
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
    ],
  },
] as mcp.Toolset[]

const regularTools = (() => {
  let a: mcp.Tool[] = []

  for (let t of regularToolsets) {
    a.push(...t.tools)
  }

  return a
})()

export type ServerConfig = {
  dynamic: boolean
  tools: string[]
  elicitation: ServerElicitation
  progress: ServerProgress
  client: apiCore.Client
  resolver: apiExtra.Resolver
  uploader: apiExtra.Uploader
  fileOperationCaller: apiExtra.FileOperationCaller
  officeApiReference: officeApi.Reference
}

export type ServerElicitation = {
  form(m: string, s: mcp.ElicitationFormRequestedSchema): Promise<r.Result<types.ElicitResult, Error>>
}

export type ServerProgress = {
  notify(p: number, m: string): Promise<void>
}

export type ServerFileOperationCaller = {
  call(fn: apiExtra.FileOperationFn): Promise<apiExtra.FileOperationIter>
}

export class Server {
  private callMetaToolHandlers: Record<string, CallToolHandler | undefined> = {
    call_tool: this.handleCallTool.bind(this),
    get_tool_input_schema: this.handleGetToolInputSchema.bind(this),
    get_tool_output_schema: this.handleGetToolOutputSchema.bind(this),
    list_tools: this.handleListTools.bind(this),
    list_toolsets: this.handleListToolsets.bind(this),
  }

  private callRegularToolHandlers: Record<string, CallToolHandler | undefined> = {
    archive_room: this.handleArchiveRoom.bind(this),
    copy_batch_items: this.handleCopyBatchItems.bind(this),
    create_folder: this.handleCreateFolder.bind(this),
    create_room: this.handleCreateRoom.bind(this),
    delete_file: this.handleDeleteFile.bind(this),
    delete_folder: this.handleDeleteFolder.bind(this),
    download_file_as_text: this.handleDownloadFileAsText.bind(this),
    get_all_people: this.handleGetAllPeople.bind(this),
    get_file_info: this.handleGetFileInfo.bind(this),
    get_folder_content: this.handleGetFolderContent.bind(this),
    get_folder_info: this.handleGetFolderInfo.bind(this),
    get_my_folder: this.handleGetMyFolder.bind(this),
    get_office_api_reference: this.handleGetOfficeApiReference.bind(this),
    get_room_access_levels: this.handleGetRoomAccessLevels.bind(this),
    get_room_info: this.handleGetRoomInfo.bind(this),
    get_room_security_info: this.handleGetRoomSecurityInfo.bind(this),
    get_room_types: this.handleGetRoomTypes.bind(this),
    get_rooms_folder: this.handleGetRoomsFolder.bind(this),
    move_batch_items: this.handleMoveBatchItems.bind(this),
    rename_folder: this.handleRenameFolder.bind(this),
    run_builder_script: this.handleRunBuilderScript.bind(this),
    set_room_security: this.handleSetRoomSecurity.bind(this),
    update_file: this.handleUpdateFile.bind(this),
    update_room: this.handleUpdateRoom.bind(this),
    upload_file: this.handleUploadFile.bind(this),
  }

  private dynamic: boolean
  private regularToolsets: mcp.Toolset[] = []
  private regularTools: mcp.Tool[] = []

  private elicitation: ServerElicitation
  private client: apiCore.Client
  private resolver: apiExtra.Resolver
  private uploader: apiExtra.Uploader
  private fileOperationCaller: apiExtra.FileOperationCaller
  private officeApiReference: officeApi.Reference

  constructor(config: ServerConfig) {
    this.dynamic = config.dynamic

    for (let x of regularToolsets) {
      let y: mcp.Toolset = {
        name: x.name,
        description: x.description,
        tools: [],
      }

      for (let a of x.tools) {
        for (let b of config.tools) {
          if (a.name === b) {
            y.tools.push(a)
            break
          }
        }
      }

      if (y.tools.length !== 0) {
        this.regularToolsets.push(y)
        this.regularTools.push(...y.tools)
      }
    }

    for (let x of Object.keys(this.callRegularToolHandlers)) {
      let f = false

      for (let y of this.regularTools) {
        if (x === y.name) {
          f = true
          break
        }
      }

      if (!f) {
        delete this.callRegularToolHandlers[x]
      }
    }

    this.elicitation = config.elicitation
    this.client = config.client
    this.resolver = config.resolver
    this.uploader = config.uploader
    this.fileOperationCaller = config.fileOperationCaller
    this.officeApiReference = config.officeApiReference
  }

  router(): mcp.Router {
    let r: mcp.Router = {
      capabilities: {
        tools: {},
      },
      handlers: {},
    }

    if (this.dynamic) {
      r.handlers["tools/call"] = this.handleMetaCallTool.bind(this)
      r.handlers["tools/list"] = this.handleMetaListTools.bind(this)
    } else {
      r.handlers["tools/call"] = this.handleRegularCallTool.bind(this)
      r.handlers["tools/list"] = this.handleRegularListTools.bind(this)
    }

    r.handlers["tools/call"] = ((h) => {
      return async(...args) => {
        try {
          return await h(...args)
        } catch (err) {
          if (err instanceof Error) {
            return fromError(err)
          }
          return fromError(new Error("Non-Error thrown", {cause: err}))
        }
      }
    })(r.handlers["tools/call"])

    return r
  }

  private async handleMetaCallTool(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let h = this.callMetaToolHandlers[req.params.name]
    if (!h) {
      return fromError(new Error(`Tool ${req.params.name} not found`))
    }
    return await h(req)
  }

  private async handleRegularCallTool(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let h = this.callRegularToolHandlers[req.params.name]
    if (!h) {
      return fromError(new Error(`Tool ${req.params.name} not found`))
    }
    return await h(req)
  }

  private handleMetaListTools(): types.ListToolsResult {
    return {
      tools: metaTools,
    }
  }

  private handleRegularListTools(): types.ListToolsResult {
    return {
      tools: this.regularTools,
    }
  }

  private async handleCallTool(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = CallToolInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    req = {
      ...req,
      params: {
        ...req.params,
      },
    }

    req.params.name = pr.data.tool
    req.params.arguments = pr.data.input

    return await this.handleRegularCallTool(req)
  }

  private handleGetToolInputSchema(req: types.CallToolRequest): types.CallToolResult {
    let pr = GetToolInputSchemaInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let i: mcp.ToolInputSchema | undefined

    for (let x of this.regularToolsets) {
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
      return fromError(new Error(`Tool '${pr.data.tool}' not found.`))
    }

    return fromObject(i)
  }

  private handleGetToolOutputSchema(req: types.CallToolRequest): types.CallToolResult {
    let pr = GetToolInputSchemaInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let o: mcp.ToolOutputSchema | undefined

    for (let x of this.regularToolsets) {
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
      return fromError(new Error(`Tool '${pr.data.tool}' not found.`))
    }

    return fromObject(o)
  }

  private handleListTools(req: types.CallToolRequest): types.CallToolResult {
    let pr = ListToolsInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let s: mcp.Toolset | undefined

    for (let t of this.regularToolsets) {
      if (t.name === pr.data.toolset) {
        s = t
        break
      }
    }

    if (!s) {
      return fromError(new Error(`Toolset '${pr.data.toolset}' not found.`))
    }

    let summaries: mcp.ToolSummary[] = []

    for (let t of s.tools) {
      let s: mcp.ToolSummary = {
        name: t.name,
        description: t.description,
      }
      summaries.push(s)
    }

    if (summaries.length === 0) {
      return fromError(new Error(`No tools found for toolset '${pr.data.toolset}'.`))
    }

    return fromObject(summaries)
  }

  private handleListToolsets(): types.CallToolResult {
    let summaries: mcp.ToolSummary[] = []

    for (let t of this.regularToolsets) {
      let s: mcp.ToolSummary = {
        name: t.name,
        description: t.description,
      }
      summaries.push(s)
    }

    if (summaries.length === 0) {
      return fromError(new Error("No toolsets found."))
    }

    return fromObject(summaries)
  }

  private async handleArchiveRoom(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = ArchiveRoomInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let ar = await this.client.files.archiveRoom(pr.data.roomId, {})
    if (ar.err) {
      return fromError(new Error("Archiving room.", {cause: ar.err}))
    }

    let [ad] = ar.v

    let rr = await this.resolver.resolve(ad)
    if (rr.err) {
      return fromError(new Error("Resolving archive room operations.", {cause: rr.err}))
    }

    return fromString("Room archived.")
  }

  private async handleCopyBatchItems(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = CopyBatchItemsInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let co: core.CopyBatchItemsOptions = {
      // @ts-expect-error See the type above for the reason.
      folderIds: pr.data.folderIds,
      // @ts-expect-error See the type above for the reason.
      fileIds: pr.data.fileIds,
      // @ts-expect-error See the type above for the reason.
      destFolderId: pr.data.destFolderId,
      conflictResolveType: 2,
      deleteAfter: false,
    }

    let cr = await this.client.files.copyBatchItems(co)
    if (cr.err) {
      return fromError(new Error("Copying batch items.", {cause: cr.err}))
    }

    let [cd] = cr.v

    let rr = await this.resolver.resolve(...cd)
    if (rr.err) {
      return fromError(new Error("Resolving copy batch items operations.", {cause: rr.err}))
    }

    return fromString("Batch items copied.")
  }

  private async handleCreateFolder(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = CreateFolderInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let co: core.CreateFolderOptions = {
      title: pr.data.title,
    }

    let cr = await this.client.files.createFolder(pr.data.parentId, co, pr.data.filters)
    if (cr.err) {
      return fromError(new Error("Creating folder.", {cause: cr.err}))
    }

    let [, res] = cr.v

    return await fromResponse(res, CreateFolderOutputJsonSchema)
  }

  private async handleCreateRoom(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = CreateRoomInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let co: core.CreateRoomOptions = {
      title: pr.data.title,
      roomType: pr.data.roomType,
    }

    let cr = await this.client.files.createRoom(co, pr.data.filters)
    if (cr.err) {
      return fromError(new Error("Creating room.", {cause: cr.err}))
    }

    let [, res] = cr.v

    return await fromResponse(res, CreateRoomOutputJsonSchema)
  }

  private async handleDeleteFile(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = DeleteFileInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let tr = await this.client.files.getTrashFolder()
    if (tr.err) {
      return fromError(new Error("Getting trash folder.", {cause: tr.err}))
    }

    let [td] = tr.v

    if (!td.current) {
      return fromError(new Error("Trash folder is not defined."))
    }

    if (!td.current.id) {
      return fromError(new Error("Trash folder ID is not defined."))
    }

    let fr = await this.client.files.getFileInfo(pr.data.fileId)
    if (fr.err) {
      return fromError(new Error("Getting file info.", {cause: fr.err}))
    }

    let [gd] = fr.v

    if (!gd.folderId) {
      return fromError(new Error("File folder ID is not defined."))
    }

    if (gd.folderId === td.current.id) {
      return fromString("File is already in the trash folder.")
    }

    let dp: core.DeleteFileOptions = {
      deleteAfter: false,
      immediately: false,
    }

    let dr = await this.client.files.deleteFile(pr.data.fileId, dp)
    if (dr.err) {
      return fromError(new Error("Deleting file.", {cause: dr.err}))
    }

    let [dd] = dr.v

    let rr = await this.resolver.resolve(...dd)
    if (rr.err) {
      return fromError(new Error("Resolving delete file operations.", {cause: rr.err}))
    }

    return fromString("File deleted.")
  }

  private async handleDeleteFolder(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = DeleteFolderInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let dp: core.DeleteFolderOptions = {
      deleteAfter: false,
      immediately: false,
    }

    let dr = await this.client.files.deleteFolder(pr.data.folderId, dp)
    if (dr.err) {
      return fromError(new Error("Deleting folder.", {cause: dr.err}))
    }

    let [dd] = dr.v

    let rr = await this.resolver.resolve(...dd)
    if (rr.err) {
      return fromError(new Error("Resolving delete folder operations.", {cause: rr.err}))
    }

    return fromString("Folder deleted.")
  }

  private async handleDownloadFileAsText(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = DownloadFileAsTextInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let ir = await this.client.files.getFileInfo(pr.data.fileId)
    if (ir.err) {
      return fromError(new Error("Getting file info.", {cause: ir.err}))
    }

    let [id] = ir.v

    if (!id.fileExst) {
      return fromError(new Error("File extension is not defined."))
    }

    let ex: string | undefined

    if (id.fileExst === ".csv" || id.fileExst === ".txt") {
      ex = id.fileExst
    } else {
      let sr = await this.client.files.getFilesSettings()
      if (sr.err) {
        return fromError(new Error("Getting files settings.", {cause: sr.err}))
      }

      let [sd] = sr.v

      if (!sd.extsConvertible) {
        return fromError(new Error("Convertible file extensions are not defined."))
      }

      let fr = sd.extsConvertible[id.fileExst]

      if (!fr) {
        return fromError(new Error(`File extension ${id.fileExst} is not convertible.`))
      }

      for (let e of fr) {
        if (e === ".csv" || e === ".txt") {
          ex = e
          break
        }
      }
    }

    if (!ex) {
      return fromError(new Error(`No convertible extension found for ${id.fileExst}.`))
    }

    let bo: core.BulkDownloadOptions = {
      fileConvertIds: [{key: pr.data.fileId, value: ex}],
    }

    let br = await this.client.files.bulkDownload(bo)
    if (br.err) {
      return fromError(new Error("Making bulk download.", {cause: br.err}))
    }

    let [bd] = br.v

    let rr = await this.resolver.resolve(...bd)
    if (rr.err) {
      return fromError(new Error("Resolving bulk download operations.", {cause: rr.err}))
    }

    if (rr.v.operations.length === 0) {
      return fromError(new Error("No resolved operations."))
    }

    if (rr.v.operations.length > 1) {
      return fromError(new Error(`Expected 1 resolved operation, got ${rr.v.operations.length}.`))
    }

    let [rd] = rr.v.operations

    if (rd.url === undefined) {
      return fromError(new Error("Resolved operation has no URL."))
    }

    let dr = this.client.createRequest("GET", rd.url)
    if (dr.err) {
      return fromError(new Error("Creating download request.", {cause: dr.err}))
    }

    let hr = r.safeSync(dr.v.headers.set.bind(dr.v.headers), "Accept", "text/plain")
    if (hr.err) {
      return fromError(new Error("Setting header.", {cause: hr.err}))
    }

    let tr = await this.client.bareFetch(dr.v)
    if (tr.err) {
      return fromError(new Error("Downloading file.", {cause: tr.err}))
    }

    let tt = await r.safeAsync(tr.v.text.bind(tr.v))
    if (tt.err) {
      return fromError(new Error("Converting response to text.", {cause: tt.err}))
    }

    return fromString(tt.v)
  }

  private async handleGetAllPeople(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = GetAllPeopleInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let gr = await this.client.people.getFullByFilter(pr.data.filters)
    if (gr.err) {
      return fromError(new Error("Getting people.", {cause: gr.err}))
    }

    let [, res] = gr.v

    return await fromResponse(res, GetAllPeopleOutputJsonSchema)
  }

  private async handleGetFileInfo(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = GetFileInfoInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let gr = await this.client.files.getFileInfo(pr.data.fileId, pr.data.filters)
    if (gr.err) {
      return fromError(new Error("Getting file info.", {cause: gr.err}))
    }

    let [, res] = gr.v

    return await fromResponse(res, GetFileInfoOutputJsonSchema)
  }

  private async handleGetFolderContent(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = GetFolderContentInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let gr = await this.client.files.getFolder(pr.data.folderId, pr.data.filters)
    if (gr.err) {
      return fromError(new Error("Getting folder.", {cause: gr.err}))
    }

    let [, res] = gr.v

    return await fromResponse(res, GetFolderContentOutputJsonSchema)
  }

  private async handleGetFolderInfo(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = GetFolderInfoInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let gr = await this.client.files.getFolderInfo(pr.data.folderId, pr.data.filters)
    if (gr.err) {
      return fromError(new Error("Getting folder info.", {cause: gr.err}))
    }

    let [, res] = gr.v

    return await fromResponse(res, GetFolderInfoOutputJsonSchema)
  }

  private async handleGetMyFolder(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = GetMyFolderInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let gr = await this.client.files.getMyFolder(pr.data.filters)
    if (gr.err) {
      return fromError(new Error("Getting my folder.", {cause: gr.err}))
    }

    let [, res] = gr.v

    return await fromResponse(res, GetMyFolderOutputJsonSchema)
  }

  private async handleGetOfficeApiReference(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = GetOfficeApiReferenceInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    if (pr.data.method !== undefined && pr.data.class === undefined) {
      return fromError(new Error("The method has to be given together with its class."))
    }

    let ir = await this.officeApiReference.index(pr.data.editor)
    if (ir.err) {
      return fromError(new Error("Getting reference index.", {cause: ir.err}))
    }

    let a = ir.v

    if (pr.data.class !== undefined) {
      let n = pr.data.class
      let k: officeApi.ReferenceEntryKind[] = ["class", "enumeration"]

      if (pr.data.method !== undefined) {
        n = `${pr.data.class}.${pr.data.method}`
        k = ["method"]
      }

      let en = officeApi.findEntry(a, n, k)

      if (!en) {
        return fromError(new Error(officeApi.notFoundMessage(a, pr.data.editor, pr.data.class, pr.data.method)))
      }

      let pg = await this.officeApiReference.page(en)
      if (pg.err) {
        return fromError(new Error("Getting reference page.", {cause: pg.err}))
      }

      return fromString(pg.v)
    }

    if (pr.data.query !== undefined) {
      let f = officeApi.searchEntries(a, pr.data.query)

      if (f.length === 0) {
        return fromString(`Nothing in the ${pr.data.editor} API matches "${pr.data.query}". Try other words, or call the tool without query for the list of classes.`)
      }

      let m = 50
      let t = ""

      for (let e of f.slice(0, m)) {
        t += `- ${e.name} (${e.kind}): ${e.description}\n`
      }

      if (f.length > m) {
        t += `\n${f.length - m} more matches are not shown; add words to the query to narrow it.\n`
      }

      return fromString(t.trim())
    }

    let ov = a.find((e) => e.kind === "overview")

    let t = ""

    if (ov) {
      let pg = await this.officeApiReference.page(ov)
      if (pg.err) {
        return fromError(new Error("Getting reference overview.", {cause: pg.err}))
      }

      t += `${pg.v}\n\n`
    }

    t += "## Classes\n\n"

    for (let e of a) {
      if (e.kind === "class") {
        t += `- ${e.name}: ${e.description}\n`
      }
    }

    t += "\n## Enumerations\n\n"

    let en: string[] = []

    for (let e of a) {
      if (e.kind === "enumeration") {
        en.push(e.name)
      }
    }

    t += `${en.join(", ")}\n\n`
    t += "Pass class to get the methods of a class or the values of an enumeration, class and method to get a method, and query to search."

    return fromString(t)
  }

  private async handleGetRoomAccessLevels(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = GetRoomAccessLevelsInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let gr = await this.client.files.getRoomInfo(pr.data.roomId)
    if (gr.err) {
      return fromError(new Error("Getting room info.", {cause: gr.err}))
    }

    let [gd] = gr.v

    if (!gd.roomType) {
      return fromError(new Error("Room type is not defined."))
    }

    let sh: z.ZodType | undefined

    switch (gd.roomType) {
    case 1:
      sh = FormFillingRoomInvitationAccessSchema
      break
    case 2:
      sh = CollaborationRoomInvitationAccessSchema
      break
    case 5:
      sh = CustomRoomInvitationAccessSchema
      break
    case 6:
      sh = PublicRoomInvitationAccessSchema
      break
    case 8:
      sh = VirtualDataRoomInvitationAccessSchema
      break
    default:
      sh = RoomInvitationAccessSchema
      break
    }

    return fromObject(z.toJSONSchema(sh))
  }

  private async handleGetRoomInfo(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = GetRoomInfoInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let gr = await this.client.files.getRoomInfo(pr.data.roomId, pr.data.filters)
    if (gr.err) {
      return fromError(new Error("Getting room info.", {cause: gr.err}))
    }

    let [, res] = gr.v

    return await fromResponse(res, GetRoomInfoOutputJsonSchema)
  }

  private async handleGetRoomSecurityInfo(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = GetRoomSecurityInfoInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let gr = await this.client.files.getRoomSecurityInfo(pr.data.roomId, pr.data.filters)
    if (gr.err) {
      return fromError(new Error("Getting room security info.", {cause: gr.err}))
    }

    let [, res] = gr.v

    return await fromResponse(res, GetRoomSecurityInfoOutputJsonSchema)
  }

  private handleGetRoomTypes(): types.CallToolResult {
    return fromObject(z.toJSONSchema(core.RoomTypeSchema))
  }

  private async handleGetRoomsFolder(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = GetRoomsFolderInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let gr = await this.client.files.getRoomsFolder(pr.data.filters)
    if (gr.err) {
      return fromError(new Error("Getting rooms folder.", {cause: gr.err}))
    }

    let [, res] = gr.v

    return await fromResponse(res, GetRoomsFolderOutputJsonSchema)
  }

  private async handleMoveBatchItems(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = MoveBatchItemsInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let mo: core.MoveBatchItemsOptions = {
      // @ts-expect-error See the type above for the reason.
      folderIds: pr.data.folderIds,
      // @ts-expect-error See the type above for the reason.
      fileIds: pr.data.fileIds,
      // @ts-expect-error See the type above for the reason.
      destFolderId: pr.data.destFolderId,
      conflictResolveType: 2,
      deleteAfter: false,
    }

    let mr = await this.client.files.moveBatchItems(mo)
    if (mr.err) {
      return fromError(new Error("Moving batch items.", {cause: mr.err}))
    }

    let [md] = mr.v

    let rr = await this.resolver.resolve(...md)
    if (rr.err) {
      return fromError(new Error("Resolving move batch items operations.", {cause: rr.err}))
    }

    return fromString("Batch items moved.")
  }

  private async handleRenameFolder(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = RenameFolderInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let ro: core.RenameFolderOptions = {
      title: pr.data.title,
    }

    let rr = await this.client.files.renameFolder(pr.data.folderId, ro, pr.data.filters)
    if (rr.err) {
      return fromError(new Error("Renaming folder.", {cause: rr.err}))
    }

    let [, res] = rr.v

    return await fromResponse(res, RenameFolderOutputJsonSchema)
  }

  private async handleRunBuilderScript(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = RunBuilderScriptInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let ro: core.RunBuilderScriptOptions = {
      script: pr.data.script,
      folderId: pr.data.folderId,
      outputs: pr.data.outputs,
      argument: pr.data.argument,
    }

    let it = await this.fileOperationCaller.call(() => this.client.files.runBuilderScript(ro))

    for await (let _ of it) {
      // Wait for the operation to finish.
    }

    let rr = it.result()
    if (rr.err) {
      let h = builderErrorHint(rr.err)
      if (h) {
        return fromError(new Error("Running builder script.", {cause: new AggregateError([rr.err, new Error(h)])}))
      }
      return fromError(new Error("Running builder script.", {cause: rr.err}))
    }

    // The operation may end without a single status having been received.
    if (!rr.v) {
      return fromError(new Error("Builder script operation has no result."))
    }

    let files: unknown[] = []

    if (Array.isArray(rr.v.files)) {
      for (let f of rr.v.files) {
        files.push(pickFields(f, pr.data.filters.fields))
      }
    }

    return fromObject({files}, RunBuilderScriptOutputJsonSchema)
  }

  private async handleSetRoomSecurity(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = SetRoomSecurityInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let so: core.SetRoomSecurityOptions = {
      invitations: pr.data.invitations,
      notify: pr.data.notify,
      message: pr.data.message,
    }

    let sr = await this.client.files.setRoomSecurity(pr.data.roomId, so, pr.data.filters)
    if (sr.err) {
      return fromError(new Error("Setting room security.", {cause: sr.err}))
    }

    let [, res] = sr.v

    return await fromResponse(res, SetRoomSecurityOutputJsonSchema)
  }

  private async handleUpdateFile(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = UpdateFileInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let uo: core.UpdateFileOptions = {
      title: pr.data.title,
    }

    let ur = await this.client.files.updateFile(pr.data.fileId, uo)
    if (ur.err) {
      return fromError(new Error("Updating file.", {cause: ur.err}))
    }

    let [, res] = ur.v

    return await fromResponse(res, UpdateFileOutputJsonSchema)
  }

  private async handleUpdateRoom(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = UpdateRoomInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let uo: core.UpdateRoomOptions = {
      title: pr.data.title,
    }

    let ur = await this.client.files.updateRoom(pr.data.roomId, uo, pr.data.filters)
    if (ur.err) {
      return fromError(new Error("Updating room.", {cause: ur.err}))
    }

    let [, res] = ur.v

    return await fromResponse(res, UpdateRoomOutputJsonSchema)
  }

  private async handleUploadFile(req: types.CallToolRequest): Promise<types.CallToolResult> {
    let pr = UploadFileInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let fp = path.parse(pr.data.filename)

    if (!fp.ext) {
      return fromError(new Error("File extension is missing in the filename."))
    }

    let te = new TextEncoder()

    let buf = te.encode(pr.data.content)

    let so: core.CreateUploadSessionOptions = {
      fileName: pr.data.filename,
      fileSize: buf.length,
      createOn: new Date().toISOString(),
      createNewIfExist: true,
    }

    let sr = await this.client.files.createUploadSession(pr.data.parentId, so)
    if (sr.err) {
      return fromError(new Error("Creating upload session.", {cause: sr.err}))
    }

    let [sd] = sr.v

    if (sd.id === undefined) {
      return fromError(new Error("Upload session ID is not defined."))
    }

    let ur = await this.uploader.upload(sd.id, buf)
    if (ur.err) {
      return fromError(new Error("Uploading file.", {cause: ur.err}))
    }

    let [, res] = ur.v

    return await fromResponse(res)
  }
}

export class ErroredServer {
  private err: Error

  constructor(err: Error) {
    this.err = err
  }

  router(): mcp.Router {
    return {
      capabilities: {
        tools: {},
      },
      handlers: {
        "tools/call": this.handleCallTool.bind(this),
        "tools/list": this.handleListTools.bind(this),
      },
    }
  }

  private handleCallTool(): types.CallToolResult {
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

  private handleListTools(): types.ListToolsResult {
    return {
      tools: regularTools,
    }
  }
}

// Fields address nested values with dots, such as createdBy.displayName.
function pickFields(v: unknown, fields: string[]): unknown {
  if (typeof v !== "object" || v === null) {
    return v
  }

  let o: Record<string, unknown> = {}

  for (let f of fields) {
    let s: unknown = v
    let d = o
    let k = f.split(".")

    for (let [i, p] of k.entries()) {
      if (typeof s !== "object" || s === null || !(p in s)) {
        break
      }

      s = (s as Record<string, unknown>)[p]

      if (i === k.length - 1) {
        d[p] = s
        break
      }

      if (typeof d[p] !== "object" || d[p] === null) {
        d[p] = {}
      }

      d = d[p] as Record<string, unknown>
    }
  }

  return o
}

// Document Builder reports no details on a failed script, only one of the
// codes from
// https://api.onlyoffice.com/docs/docs-api/additional-api/document-builder-api#possible-error-codes-and-their-description,
// which the portal puts at the end of the operation error as "error -3".
const builderErrorHints: Record<string, string> = {
  "-1": "Document Builder error -1 (unknown error): the script failed for a reason Document Builder does not report.",
  "-2": "Document Builder error -2 (generation timeout): the script ran too long. Make it do less, or split the work across several scripts.",
  "-3": "Document Builder error -3 (document generation error): the script threw. Document Builder reports neither the message nor the line, so the cause is one of: a syntax error, a call to a method that does not exist in this version of the Office JavaScript API, wrong arguments, or an explicit throw. Check every class and method the script uses against the Office JavaScript API reference, fix the script and run it again; if the cause is still unclear, run a shorter part of the script to find the failing line.",
  "-4": "Document Builder error -4 (download error): the document opened with builder.OpenFile could not be downloaded. Check that the file ID is right and the file is accessible.",
  "-6": "Document Builder error -6 (result database error): a server-side failure unrelated to the script. Try again later.",
  "-8": "Document Builder error -8 (invalid token): the portal and ONLYOFFICE Docs are misconfigured, which no change to the script fixes. Tell the user to contact the portal administrator.",
}

function builderErrorHint(err: unknown): string | undefined {
  if (err instanceof AggregateError) {
    for (let e of err.errors) {
      let h = builderErrorHint(e)
      if (h) {
        return h
      }
    }
  }

  if (err instanceof Error) {
    let m = /\berror (-\d+)\)\s*$/.exec(err.message)
    if (m && Object.hasOwn(builderErrorHints, m[1])) {
      return builderErrorHints[m[1]]
    }

    return builderErrorHint(err.cause)
  }

  return
}

function fromError(err: Error): types.CallToolResult {
  return {
    content: [
      {
        type: "text",
        text: errors.format(err),
      },
    ],
    isError: true,
  }
}

async function fromResponse(res: apiCore.Response, s?: z.core.JSONSchema.JSONSchema): Promise<types.CallToolResult> {
  let h = res.response.headers.get("Content-Type")
  if (h === null) {
    return fromError(new Error("Content-Type header is missing"))
  }

  if (h.startsWith("application/json")) {
    let j = await r.safeAsync(res.response.json.bind(res.response))
    if (j.err) {
      return fromError(new Error("Parsing json response", {cause: j.err}))
    }

    let t = r.safeSync(JSON.stringify, j.v, undefined, 2)
    if (t.err) {
      return fromError(new Error("Stringifying json value", {cause: t.err}))
    }

    let c: types.CallToolResult = {
      content: [
        {
          type: "text",
          text: t.v,
        },
      ],
    }

    if (s) {
      c.structuredContent = j.v
    }

    return c
  }

  if (h.startsWith("text/")) {
    let t = await r.safeAsync(res.response.text.bind(res.response))
    if (t.err) {
      return fromError(new Error("Parsing text response", {cause: t.err}))
    }

    let c: types.CallToolResult = {
      content: [
        {
          type: "text",
          text: t.v,
        },
      ],
    }

    return c
  }

  return fromError(new Error(`Content-Type ${h} is not supported`))
}

function fromObject(o: object, s?: z.core.JSONSchema.JSONSchema): types.CallToolResult {
  let t = r.safeSync(JSON.stringify, o, undefined, 2)
  if (t.err) {
    return fromError(new Error("Stringifying object value", {cause: t.err}))
  }

  let c: types.CallToolResult = {
    content: [
      {
        type: "text",
        text: t.v,
      },
    ],
  }

  if (s) {
    c.structuredContent = o as Record<string, unknown>
  }

  return c
}

function fromString(s: string): types.CallToolResult {
  return {
    content: [
      {
        type: "text",
        text: s,
      },
    ],
  }
}
