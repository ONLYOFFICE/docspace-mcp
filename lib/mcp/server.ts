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

const CallToolInputJsonSchema = z.toJSONSchema(CallToolInputSchema, {io: "input"})

const GetToolInputSchemaInputSchema = z.object({
  tool: z.string().describe("The name of the tool to get input schema for."),
})

const GetToolInputSchemaInputJsonSchema = z.toJSONSchema(GetToolInputSchemaInputSchema, {io: "input"})

const GetToolOutputSchemaInputSchema = z.object({
  tool: z.string().describe("The name of the tool to get output schema for."),
})

const GetToolOutputSchemaInputJsonSchema = z.toJSONSchema(GetToolOutputSchemaInputSchema, {io: "input"})

const ListToolsInputSchema = z.object({
  toolset: z.string().describe("The name of the toolset to list tools from."),
})

const ListToolsInputJsonSchema = z.toJSONSchema(ListToolsInputSchema, {io: "input"})

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

const InstructionsRoomInvitationAccessSchema = z.union([
  RoomInvitationAccessSchema._zod.def.options[1],
  RoomInvitationAccessSchema._zod.def.options[5],
  RoomInvitationAccessSchema._zod.def.options[6],
  RoomInvitationAccessSchema._zod.def.options[7],
])

const KnowledgeRoomInvitationAccessSchema = z.union([
  RoomInvitationAccessSchema._zod.def.options[1],
  RoomInvitationAccessSchema._zod.def.options[5],
  RoomInvitationAccessSchema._zod.def.options[7],
])

const AiProjectInvitationAccessSchema = z.union([
  z.literal(2).describe("Member. Members chat in the project and read the linked instructions and knowledge rooms."),
  z.literal(9).describe("Project manager (Paid). Project managers also change the project, its linked rooms and its model, and invite new users."),
])

const ArchiveRoomInputSchema = z.object({
  roomId: z.number().describe("The ID of the room to archive."),
})

const ArchiveRoomInputJsonSchema = z.toJSONSchema(ArchiveRoomInputSchema, {io: "input"})

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

const CopyBatchItemsInputJsonSchema = z.toJSONSchema(CopyBatchItemsInputSchema, {io: "input"})

const CreateFolderInputSchema = z.object({
  parentId: z.number().describe("The ID of the room or folder to create the folder in."),
  title: z.string().describe("The title of the folder to create."),
  filters: core.CreateFolderFiltersSchema.describe("The filters to apply to the folder creation. Use them to reduce the size of the response."),
})

const CreateFolderInputJsonSchema = z.toJSONSchema(CreateFolderInputSchema, {io: "input"})

const CreateFolderOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.FolderDtoSchema.describe("The created folder information."),
})

const CreateFolderOutputJsonSchema = z.toJSONSchema(CreateFolderOutputSchema)

const CreateRoomInputSchema = z.object({
  title: z.string().describe("The title of the room to create."),
  roomType: unionToEnum(core.RoomTypeSchema, "The type of the room to create.").optional().default(6),
  filters: core.CreateRoomFiltersSchema.describe("The filters to apply to the room creation."),
})

const CreateRoomInputJsonSchema = z.toJSONSchema(CreateRoomInputSchema, {io: "input"})

const CreateRoomOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.FolderContentDtoSchema.describe("The contents of the created room."),
})

const CreateRoomOutputJsonSchema = z.toJSONSchema(CreateRoomOutputSchema)

const DeleteFileInputSchema = z.object({
  fileId: z.number().describe("The ID of the file to delete."),
})

const DeleteFileInputJsonSchema = z.toJSONSchema(DeleteFileInputSchema, {io: "input"})

const DeleteFolderInputSchema = z.object({
  folderId: z.number().describe("The ID of the folder to delete."),
})

const DeleteFolderInputJsonSchema = z.toJSONSchema(DeleteFolderInputSchema, {io: "input"})

const downloadTextDefaultLimit = 100_000
const downloadTextMaxLimit = 500_000

// The files in these formats are already plain text, so they are downloaded as
// they are, while the files in other formats are converted to plain text first.
// The conversion would drop the markup, such as the frontmatter of a skill.
const plainTextExts = new Set([".txt", ".csv", ".md", ".markdown", ".json", ".xml", ".yaml", ".yml"])

const DownloadFileAsTextInputSchema = z.object({
  fileId: z.number().describe("The ID of the file to download as text."),
  offset: z.number().int().min(0).optional().describe("The character offset to start reading from. Defaults to 0."),
  limit: z.number().int().min(1).max(downloadTextMaxLimit).optional().describe(`The maximum number of characters to return. Defaults to ${downloadTextDefaultLimit}. If the text is truncated, the response ends with a note on how to read the rest.`),
})

const DownloadFileAsTextInputJsonSchema = z.toJSONSchema(DownloadFileAsTextInputSchema, {io: "input"})

const GetAllPeopleInputSchema = z.object({
  filters: core.GetFullByFilterFiltersSchema.describe("The filters to apply to the list of people. Use them to reduce the size of the response."),
})

const GetAllPeopleInputJsonSchema = z.toJSONSchema(GetAllPeopleInputSchema, {io: "input"})

const GetAllPeopleOutputSchema = core.SuccessApiResponseSchema.extend({
  response: z.array(core.EmployeeDtoSchema),
})

const GetAllPeopleOutputJsonSchema = z.toJSONSchema(GetAllPeopleOutputSchema)

const GetFileInfoInputSchema = z.object({
  fileId: z.number().describe("The ID of the file to get info for."),
  filters: core.GetFileInfoFiltersSchema.describe("The filters to apply to the file info. Use them to reduce the size of the response."),
})

const GetFileInfoInputJsonSchema = z.toJSONSchema(GetFileInfoInputSchema, {io: "input"})

const GetFileInfoOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.FileDtoSchema.describe("The file information."),
})

const GetFileInfoOutputJsonSchema = z.toJSONSchema(GetFileInfoOutputSchema)

const GetFolderContentInputSchema = z.object({
  folderId: z.number().describe("The ID of the folder to get."),
  filters: core.GetFolderFiltersSchema.describe("The filters to apply to the contents of the folder. Use them to reduce the size of the response."),
})

const GetFolderContentInputJsonSchema = z.toJSONSchema(GetFolderContentInputSchema, {io: "input"})

const GetFolderContentOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.FolderContentDtoSchema.describe("The contents of the folder."),
})

const GetFolderContentOutputJsonSchema = z.toJSONSchema(GetFolderContentOutputSchema)

const GetFolderInfoInputSchema = z.object({
  folderId: z.number().describe("The ID of the folder to get info for."),
  filters: core.GetFolderInfoFiltersSchema.describe("The filters to apply to the folder info. Use them to reduce the size of the response."),
})

const GetFolderInfoInputJsonSchema = z.toJSONSchema(GetFolderInfoInputSchema, {io: "input"})

const GetFolderInfoOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.FolderDtoSchema.describe("The folder information."),
})

const GetFolderInfoOutputJsonSchema = z.toJSONSchema(GetFolderInfoOutputSchema)

const GetMyFolderInputSchema = z.object({
  filters: core.GetMyFolderFiltersSchema.describe("The filters to apply to the 'Files' folder (formerly 'My Documents'). Use them to reduce the size of the response."),
})

const GetMyFolderInputJsonSchema = z.toJSONSchema(GetMyFolderInputSchema, {io: "input"})

const GetMyFolderOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.FolderContentDtoSchema.describe("The contents of the 'Files' folder (formerly 'My Documents')."),
})

const GetMyFolderOutputJsonSchema = z.toJSONSchema(GetMyFolderOutputSchema)

const GetOfficeApiReferenceInputSchema = z.object({
  editor: z.enum(officeApi.editors).describe("The editor whose API to look up: document, spreadsheet, presentation, form for the form fields of a document or a PDF form, or pdf."),
  query: z.string().optional().describe("Words to look for in the names and descriptions of classes, methods and enumerations, such as \"watermark\" or \"table border\". Use it to find out what to get with class and method."),
  class: z.string().optional().describe("The name of a class or an enumeration to get, such as ApiParagraph or Drawing. Without method, returns the description of the class and the list of its methods."),
  method: z.string().optional().describe("The name of a method of the class to get, such as AddText. Returns its syntax, parameters, return value and an example."),
})

const GetOfficeApiReferenceInputJsonSchema = z.toJSONSchema(GetOfficeApiReferenceInputSchema, {io: "input"})

const GetRoomAccessLevelsInputSchema = z.object({
  roomId: z.number().describe("The ID of the room to get the invitation access for."),
})

const GetRoomAccessLevelsInputJsonSchema = z.toJSONSchema(GetRoomAccessLevelsInputSchema, {io: "input"})

const GetRoomInfoInputSchema = z.object({
  roomId: z.number().describe("The ID of the room to get info for."),
  filters: core.GetRoomInfoFiltersSchema.describe("The filters to apply to the room info."),
})

const GetRoomInfoInputJsonSchema = z.toJSONSchema(GetRoomInfoInputSchema, {io: "input"})

const GetRoomInfoOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.FolderDtoSchema.describe("The room information."),
})

const GetRoomInfoOutputJsonSchema = z.toJSONSchema(GetRoomInfoOutputSchema)

const GetRoomSecurityInfoInputSchema = z.object({
  roomId: z.number().describe("The ID of the room to get a list of users with their access level for."),
  filters: core.GetRoomSecurityFiltersSchema.describe("The filters to apply to the room security info."),
})

const GetRoomSecurityInfoInputJsonSchema = z.toJSONSchema(GetRoomSecurityInfoInputSchema, {io: "input"})

const GetRoomSecurityInfoOutputSchema = core.SuccessApiResponseSchema.extend({
  response: z.array(core.FileShareDtoSchema).describe("The room security information."),
})

const GetRoomSecurityInfoOutputJsonSchema = z.toJSONSchema(GetRoomSecurityInfoOutputSchema)

const GetRoomsFolderInputSchema = z.object({
  filters: core.GetRoomsFolderFiltersSchema.describe("The filters to apply to the rooms folder."),
})

const GetRoomsFolderInputJsonSchema = z.toJSONSchema(GetRoomsFolderInputSchema, {io: "input"})

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

const MoveBatchItemsInputJsonSchema = z.toJSONSchema(MoveBatchItemsInputSchema, {io: "input"})

const RenameFolderInputSchema = z.object({
  folderId: z.number().describe("The ID of the folder to rename."),
  title: z.string().describe("The new title of the folder to set."),
  filters: core.RenameFolderFiltersSchema.describe("The filters to apply to the folder renaming. Use them to reduce the size of the response."),
})

const RenameFolderInputJsonSchema = z.toJSONSchema(RenameFolderInputSchema, {io: "input"})

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
      }).
        refine(
          (o) => (o.fileId === undefined) !== (o.folderId === undefined),
          {
            message: "Exactly one of fileId and folderId must be provided.",
          },
        ).
        refine(
          (o) => o.title === undefined || o.folderId !== undefined,
          {
            message: "Title can only be provided with folderId.",
            path: ["title"],
          },
        ),
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

const RunBuilderScriptInputJsonSchema = z.toJSONSchema(RunBuilderScriptInputSchema, {io: "input"})

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

const SetRoomSecurityInputJsonSchema = z.toJSONSchema(SetRoomSecurityInputSchema, {io: "input"})

const SetRoomSecurityOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.RoomSecurityDtoSchema.describe("The room security information after the operation."),
})

const SetRoomSecurityOutputJsonSchema = z.toJSONSchema(SetRoomSecurityOutputSchema)

const UpdateFileInputSchema = z.object({
  fileId: z.number().describe("The ID of the file to update."),
  title: z.string().describe("The new title of the file to set."),
})

const UpdateFileInputJsonSchema = z.toJSONSchema(UpdateFileInputSchema, {io: "input"})

const UpdateFileOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.FileDtoSchema.describe("The updated file information."),
})

const UpdateFileOutputJsonSchema = z.toJSONSchema(UpdateFileOutputSchema)

const UpdateRoomInputSchema = z.object({
  roomId: z.number().describe("The ID of the room to update."),
  title: z.string().optional().describe("The new title of the room to set."),
  filters: core.UpdateRoomFiltersSchema.describe("The filters to apply to the room update."),
})

const UpdateRoomInputJsonSchema = z.toJSONSchema(UpdateRoomInputSchema, {io: "input"})

const UpdateRoomOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.FolderDtoSchema.describe("The updated room information."),
})

const UpdateRoomOutputJsonSchema = z.toJSONSchema(UpdateRoomOutputSchema)

const UploadFileInputSchema = z.object({
  parentId: z.number().describe("The ID of the room or folder to upload the file to."),
  filename: z.string().describe("The file name with an extension to upload."),
  content: z.string().describe("The content of the file to upload."),
  overwrite: z.boolean().optional().describe("Whether to save the content as a new version of the file with the same name in the room or folder, keeping its ID, such as to change a skill. The former versions stay in the version history. When false or omitted, the file is uploaded as a new file and gets a new name if the name is taken."),
})

const UploadFileInputJsonSchema = z.toJSONSchema(UploadFileInputSchema, {io: "input"})

const UploadedFileSchema = z.looseObject({
  title: z.string().optional(),
})

const aiProjectIdDescription = "The ID of the AI project."

const AiProjectSourcesInputSchema = z.object({
  roomId: z.number().describe(aiProjectIdDescription),
  roomIds: z.array(z.number()).min(1).max(40).describe("The IDs of the instructions and knowledge rooms."),
})

const AiProjectSourcesInputJsonSchema = z.toJSONSchema(AiProjectSourcesInputSchema, {io: "input"})

const CreateAiRoomInputSchema = z.object({
  title: z.string().max(170).describe("The title of the room to create."),
  roomType: unionToEnum(core.AiRoomTypeSchema, "The type of the AI room to create."),
  tags: z.array(z.string()).optional().describe("The tags of the room."),
  color: z.string().regex(/^[0-9a-fA-F]{6}$/).optional().describe("The color of the room logo, a hex code of six digits without #, such as 7757D9."),
  filters: core.CreateRoomFiltersSchema.describe("The filters to apply to the room creation."),
})

const CreateAiRoomInputJsonSchema = z.toJSONSchema(CreateAiRoomInputSchema, {io: "input"})

const CreateAiRoomOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.FolderDtoSchema.describe("The created room."),
})

const CreateAiRoomOutputJsonSchema = z.toJSONSchema(CreateAiRoomOutputSchema)

const DeleteAiRoomInputSchema = z.object({
  roomId: z.number().describe("The ID of the instructions room, knowledge room or AI project to delete."),
})

const DeleteAiRoomInputJsonSchema = z.toJSONSchema(DeleteAiRoomInputSchema, {io: "input"})

const GetAiConfigOutputSchema = z.object({
  aiReady: z.boolean().describe("Specifies if AI is enabled and configured on the portal. AI rooms are available only when it is true."),
  vectorizationEnabled: z.boolean().describe("Specifies if vectorization is enabled. Knowledge rooms can be created and filled only when it is true."),
})

const GetAiConfigOutputJsonSchema = z.toJSONSchema(GetAiConfigOutputSchema)

const GetAiProfilesOutputSchema = z.object({
  profiles: z.array(z.object({
    id: z.string().describe("The profile ID to pass to set_ai_project_model."),
    name: z.string().describe("The profile name."),
    providerType: z.string().describe("The provider of the model."),
    modelId: z.string().describe("The model ID at the provider."),
    tools: z.boolean().describe("Specifies if the model can call tools."),
    vision: z.boolean().describe("Specifies if the model can read images."),
  })).describe("The chat model profiles of the portal."),
})

const GetAiProfilesOutputJsonSchema = z.toJSONSchema(GetAiProfilesOutputSchema)

const GetAiProjectModelInputSchema = z.object({
  roomId: z.number().describe(aiProjectIdDescription),
})

const GetAiProjectModelInputJsonSchema = z.toJSONSchema(GetAiProjectModelInputSchema, {io: "input"})

const GetAiProjectModelOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.AiProjectModelDtoSchema.describe("The model of the AI project chat."),
})

const GetAiProjectModelOutputJsonSchema = z.toJSONSchema(GetAiProjectModelOutputSchema)

const GetAiProjectSourcesInputSchema = z.object({
  roomId: z.number().describe(aiProjectIdDescription),
})

const GetAiProjectSourcesInputJsonSchema = z.toJSONSchema(GetAiProjectSourcesInputSchema, {io: "input"})

const GetAiProjectSourcesOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.AiProjectSourcesDtoSchema.describe("The rooms linked to the AI project."),
})

const GetAiProjectSourcesOutputJsonSchema = z.toJSONSchema(GetAiProjectSourcesOutputSchema)

const GetAiRoomsFolderInputSchema = z.object({
  filters: core.GetAiRoomsFolderFiltersSchema.describe("The filters to apply to the AI rooms section."),
})

const GetAiRoomsFolderInputJsonSchema = z.toJSONSchema(GetAiRoomsFolderInputSchema, {io: "input"})

const GetAiRoomsFolderOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.FolderContentDtoSchema.describe("The contents of the AI rooms section."),
})

const GetAiRoomsFolderOutputJsonSchema = z.toJSONSchema(GetAiRoomsFolderOutputSchema)

const GetAiSkillsInputSchema = z.object({
  roomId: z.number().describe("The ID of the instructions room or the AI project."),
})

const GetAiSkillsInputJsonSchema = z.toJSONSchema(GetAiSkillsInputSchema, {io: "input"})

const GetAiSkillsOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.AiSkillsDtoSchema.describe("The instructions rooms with their skills."),
})

const GetAiSkillsOutputJsonSchema = z.toJSONSchema(GetAiSkillsOutputSchema)

const RetryVectorizationInputSchema = z.object({
  fileIds: z.array(z.number()).min(1).describe("The IDs of the files in a knowledge room to vectorize again."),
})

const RetryVectorizationInputJsonSchema = z.toJSONSchema(RetryVectorizationInputSchema, {io: "input"})

const SetAiProjectModelInputSchema = z.object({
  roomId: z.number().describe(aiProjectIdDescription),
  profileId: z.uuid().describe("The ID of a chat model profile from get_ai_profiles."),
})

const SetAiProjectModelInputJsonSchema = z.toJSONSchema(SetAiProjectModelInputSchema, {io: "input"})

const SetAiProjectModelOutputSchema = core.SuccessApiResponseSchema.extend({
  response: core.AiProjectModelDtoSchema.describe("The model of the AI project chat."),
})

const SetAiProjectModelOutputJsonSchema = z.toJSONSchema(SetAiProjectModelOutputSchema)

// todo: remove export
export const metaTools = [
  {
    name: "list_toolsets",
    title: "List Toolsets",
    description: "This is a meta tool for listing available toolsets. Toolset is a set of available tools.",
    inputSchema: z.toJSONSchema(z.object({}), {io: "input"}),
    annotations: {
      title: "List Toolsets",
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "list_tools",
    title: "List Tools",
    description: "This is a meta tool for listing available tools of a specific toolset. The list of available toolsets can be obtained using the list_toolsets meta tool.",
    inputSchema: ListToolsInputJsonSchema,
    annotations: {
      title: "List Tools",
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "get_tool_input_schema",
    title: "Get Tool Input Schema",
    description: "This is a meta tool for getting an input schema for a specific tool. The list of available tools can be obtained using the list_tools meta tool.",
    inputSchema: GetToolInputSchemaInputJsonSchema,
    annotations: {
      title: "Get Tool Input Schema",
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "get_tool_output_schema",
    title: "Get Tool Output Schema",
    description: "This is a meta tool for getting an output schema for a specific tool. The list of available tools can be obtained using the list_tools meta tool.",
    inputSchema: GetToolOutputSchemaInputJsonSchema,
    annotations: {
      title: "Get Tool Output Schema",
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "call_tool",
    title: "Call Tool",
    description: "This is a meta tool for calling a tool. The list of available tools can be obtained using the list_tools meta tool. The input schema can be obtained using the get_tool_input_schema meta tool.",
    inputSchema: CallToolInputJsonSchema,
    annotations: {
      title: "Call Tool",
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
        title: "Delete File",
        description: "Delete a file.",
        inputSchema: DeleteFileInputJsonSchema,
        annotations: {
          title: "Delete File",
          readOnlyHint: false,
          destructiveHint: true,
          openWorldHint: false,
        },
      },
      {
        name: "get_file_info",
        title: "Get File Info",
        description: "Get file information.",
        inputSchema: GetFileInfoInputJsonSchema,
        outputSchema: GetFileInfoOutputJsonSchema,
        annotations: {
          title: "Get File Info",
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "update_file",
        title: "Update File",
        description: "Update a file.",
        inputSchema: UpdateFileInputJsonSchema,
        outputSchema: UpdateFileOutputJsonSchema,
        annotations: {
          title: "Update File",
          readOnlyHint: false,
          destructiveHint: true,
          openWorldHint: false,
        },
      },
      {
        name: "copy_batch_items",
        title: "Copy Items",
        description: "Copy to a folder.",
        inputSchema: CopyBatchItemsInputJsonSchema,
        annotations: {
          title: "Copy Items",
          readOnlyHint: false,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "move_batch_items",
        title: "Move Items",
        description: "Move to a folder.",
        inputSchema: MoveBatchItemsInputJsonSchema,
        annotations: {
          title: "Move Items",
          readOnlyHint: false,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "download_file_as_text",
        title: "Download File as Text",
        description: "Download a file as text. Text, CSV, Markdown, JSON, XML and YAML files are returned as they are, with their markup, such as the frontmatter of a skill. Documents, spreadsheets, presentations and PDF files are converted to plain text, so their formatting, images and embedded objects are lost.",
        inputSchema: DownloadFileAsTextInputJsonSchema,
        annotations: {
          title: "Download File as Text",
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "upload_file",
        title: "Upload File",
        description: "Upload a file. To change the content of a file, such as a skill, upload it with the same name and overwrite set to true.",
        inputSchema: UploadFileInputJsonSchema,
        annotations: {
          title: "Upload File",
          readOnlyHint: false,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "get_office_api_reference",
        title: "Get Office API Reference",
        description: "Look up the Office JavaScript API that run_builder_script scripts are written against. Use it before every run_builder_script call to check the methods the script uses, since the API changes between versions and remembered signatures may be outdated. Without class and query, returns an overview of the editor API with the list of its classes and enumerations; with query, finds classes, methods and enumerations; with class, returns the methods of a class or the values of an enumeration; with class and method, returns the syntax, parameters and an example of a method. The reference is read from api.onlyoffice.com.",
        inputSchema: GetOfficeApiReferenceInputJsonSchema,
        annotations: {
          title: "Get Office API Reference",
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: true,
        },
      },
      {
        name: "run_builder_script",
        title: "Run Builder Script",
        description: "Run an ONLYOFFICE Document Builder script to create or edit documents, spreadsheets, presentations or PDFs, and wait for it to finish. The Office JavaScript API changes between versions (since 9.4.0, for example, Api.CreateTable takes rows before columns), so do not write the script from memory: look up every class and method it uses with the get_office_api_reference tool first. Returns the saved files in the files field; a file may get a different title than the name passed to builder.SaveFile when the folder already has a file with that name.",
        inputSchema: RunBuilderScriptInputJsonSchema,
        outputSchema: RunBuilderScriptOutputJsonSchema,
        annotations: {
          title: "Run Builder Script",
          readOnlyHint: false,
          destructiveHint: true,
          openWorldHint: false,
        },
      },
    ],
  },
  {
    name: "folders",
    description: "Operations for working with folders, including the 'Files' section (formerly 'My Documents').",
    tools: [
      {
        name: "create_folder",
        title: "Create Folder",
        description: "Create a folder.",
        inputSchema: CreateFolderInputJsonSchema,
        outputSchema: CreateFolderOutputJsonSchema,
        annotations: {
          title: "Create Folder",
          readOnlyHint: false,
          destructiveHint: true,
          openWorldHint: false,
        },
      },
      {
        name: "delete_folder",
        title: "Delete Folder",
        description: "Delete a folder.",
        inputSchema: DeleteFolderInputJsonSchema,
        annotations: {
          title: "Delete Folder",
          readOnlyHint: false,
          destructiveHint: true,
          openWorldHint: false,
        },
      },
      {
        name: "get_folder_content",
        title: "Get Folder Content",
        description: "Get content of a folder.",
        inputSchema: GetFolderContentInputJsonSchema,
        outputSchema: GetFolderContentOutputJsonSchema,
        annotations: {
          title: "Get Folder Content",
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "get_folder_info",
        title: "Get Folder Info",
        description: "Get folder information.",
        inputSchema: GetFolderInfoInputJsonSchema,
        outputSchema: GetFolderInfoOutputJsonSchema,
        annotations: {
          title: "Get Folder Info",
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "rename_folder",
        title: "Rename Folder",
        description: "Rename a folder.",
        inputSchema: RenameFolderInputJsonSchema,
        outputSchema: RenameFolderOutputJsonSchema,
        annotations: {
          title: "Rename Folder",
          readOnlyHint: false,
          destructiveHint: true,
          openWorldHint: false,
        },
      },
      {
        name: "get_my_folder",
        title: "Get Files Folder",
        description: "Get the 'Files' folder (formerly 'My Documents').",
        inputSchema: GetMyFolderInputJsonSchema,
        outputSchema: GetMyFolderOutputJsonSchema,
        annotations: {
          title: "Get Files Folder",
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
        title: "Create Room",
        description: "Create a room.",
        inputSchema: CreateRoomInputJsonSchema,
        outputSchema: CreateRoomOutputJsonSchema,
        annotations: {
          title: "Create Room",
          readOnlyHint: false,
          destructiveHint: true,
          openWorldHint: true,
        },
      },
      {
        name: "get_room_info",
        title: "Get Room Info",
        description: "Get room information.",
        inputSchema: GetRoomInfoInputJsonSchema,
        outputSchema: GetRoomInfoOutputJsonSchema,
        annotations: {
          title: "Get Room Info",
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "update_room",
        title: "Update Room",
        description: "Update a room.",
        inputSchema: UpdateRoomInputJsonSchema,
        outputSchema: UpdateRoomOutputJsonSchema,
        annotations: {
          title: "Update Room",
          readOnlyHint: false,
          destructiveHint: true,
          openWorldHint: false,
        },
      },
      {
        name: "archive_room",
        title: "Archive Room",
        description: "Archive a room. AI rooms cannot be archived; delete them with delete_ai_room.",
        inputSchema: ArchiveRoomInputJsonSchema,
        annotations: {
          title: "Archive Room",
          readOnlyHint: false,
          destructiveHint: true,
          openWorldHint: false,
        },
      },
      {
        name: "set_room_security",
        title: "Set Room Access",
        description: "Invite or remove users from a room.",
        inputSchema: SetRoomSecurityInputJsonSchema,
        outputSchema: SetRoomSecurityOutputJsonSchema,
        annotations: {
          title: "Set Room Access",
          readOnlyHint: false,
          destructiveHint: true,
          openWorldHint: true,
        },
      },
      {
        name: "get_room_security_info",
        title: "Get Room Access Info",
        description: "Get a list of users with their access levels to a room.",
        inputSchema: GetRoomSecurityInfoInputJsonSchema,
        outputSchema: GetRoomSecurityInfoOutputJsonSchema,
        annotations: {
          title: "Get Room Access Info",
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "get_rooms_folder",
        title: "Get Rooms Folder",
        description: "Get the 'Rooms' folder.",
        inputSchema: GetRoomsFolderInputJsonSchema,
        outputSchema: GetRoomsFolderOutputJsonSchema,
        annotations: {
          title: "Get Rooms Folder",
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "get_room_types",
        title: "Get Room Types",
        description: "Get a list of available room types.",
        inputSchema: z.toJSONSchema(z.object({}), {io: "input"}),
        annotations: {
          title: "Get Room Types",
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "get_room_access_levels",
        title: "Get Room Access Levels",
        description: "Get a list of available room invitation access levels.",
        inputSchema: GetRoomAccessLevelsInputJsonSchema,
        annotations: {
          title: "Get Room Access Levels",
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
    ],
  },
  {
    name: "ai_rooms",
    description: "Operations for working with AI rooms: instructions rooms with skills, knowledge rooms with files for retrieval, and AI projects that link them, set the chat model and are shared with a team. Requires ONLYOFFICE Apps 4.1 or later with AI enabled on the portal.",
    tools: [
      {
        name: "get_ai_config",
        title: "Get AI Config",
        description: "Get whether AI and vectorization are enabled on the portal. Call it before working with AI rooms: when aiReady is false, the other AI room tools are refused, and when vectorizationEnabled is false, knowledge rooms cannot be created or filled.",
        inputSchema: z.toJSONSchema(z.object({}), {io: "input"}),
        outputSchema: GetAiConfigOutputJsonSchema,
        annotations: {
          title: "Get AI Config",
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "get_ai_rooms_folder",
        title: "Get AI Rooms Folder",
        description: "Get the AI rooms section with instructions rooms, knowledge rooms and AI projects. These rooms are not listed by get_rooms_folder.",
        inputSchema: GetAiRoomsFolderInputJsonSchema,
        outputSchema: GetAiRoomsFolderOutputJsonSchema,
        annotations: {
          title: "Get AI Rooms Folder",
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "create_ai_room",
        title: "Create AI Room",
        description: "Create an AI room. An instructions room (10) holds skills: Markdown files uploaded with upload_file into the room itself, each starting with a YAML frontmatter between two --- lines with name (lowercase letters, digits and single hyphens, up to 64 characters) and description (up to 1024 characters); a room holds up to 100 skills. A knowledge room (11) holds files that are vectorized for retrieval, such as txt, md, docx, xlsx, pptx and pdf up to 30 MB: upload text with upload_file or copy documents into it with copy_batch_items; it can be created and filled only while vectorization is enabled. An AI project (12) holds no files: link instructions and knowledge rooms to it with link_ai_project_sources, choose its chat model with set_ai_project_model and invite the team with set_room_security.",
        inputSchema: CreateAiRoomInputJsonSchema,
        outputSchema: CreateAiRoomOutputJsonSchema,
        annotations: {
          title: "Create AI Room",
          readOnlyHint: false,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "delete_ai_room",
        title: "Delete AI Room",
        description: "Delete an instructions room, a knowledge room or an AI project with all its files. The deletion is permanent: the room does not go to the trash, and AI rooms cannot be archived. Rooms of other types are refused.",
        inputSchema: DeleteAiRoomInputJsonSchema,
        annotations: {
          title: "Delete AI Room",
          readOnlyHint: false,
          destructiveHint: true,
          openWorldHint: false,
        },
      },
      {
        name: "get_ai_project_sources",
        title: "Get AI Project Sources",
        description: "Get the instructions and knowledge rooms linked to an AI project.",
        inputSchema: GetAiProjectSourcesInputJsonSchema,
        outputSchema: GetAiProjectSourcesOutputJsonSchema,
        annotations: {
          title: "Get AI Project Sources",
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "link_ai_project_sources",
        title: "Link AI Project Sources",
        description: "Link instructions and knowledge rooms to an AI project. Every member of the project gets read access to the linked rooms. A project links up to 20 rooms of each type; rooms already linked are skipped. Linking needs the right to edit the project and each room.",
        inputSchema: AiProjectSourcesInputJsonSchema,
        annotations: {
          title: "Link AI Project Sources",
          readOnlyHint: false,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "unlink_ai_project_sources",
        title: "Unlink AI Project Sources",
        description: "Unlink instructions and knowledge rooms from an AI project. The project members who are not members of a room lose access to it. Rooms that are not linked are ignored.",
        inputSchema: AiProjectSourcesInputJsonSchema,
        annotations: {
          title: "Unlink AI Project Sources",
          readOnlyHint: false,
          destructiveHint: true,
          openWorldHint: false,
        },
      },
      {
        name: "get_ai_project_model",
        title: "Get AI Project Model",
        description: "Get the chat model of an AI project. A missing or null profileId means that the project uses the default model of the portal.",
        inputSchema: GetAiProjectModelInputJsonSchema,
        outputSchema: GetAiProjectModelOutputJsonSchema,
        annotations: {
          title: "Get AI Project Model",
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "set_ai_project_model",
        title: "Set AI Project Model",
        description: "Set the chat model of an AI project to a profile from get_ai_profiles. The model can be replaced but not reset to the default model of the portal.",
        inputSchema: SetAiProjectModelInputJsonSchema,
        outputSchema: SetAiProjectModelOutputJsonSchema,
        annotations: {
          title: "Set AI Project Model",
          readOnlyHint: false,
          destructiveHint: true,
          openWorldHint: false,
        },
      },
      {
        name: "get_ai_profiles",
        title: "Get AI Profiles",
        description: "Get the chat model profiles of the portal that an AI project can use.",
        inputSchema: z.toJSONSchema(z.object({}), {io: "input"}),
        outputSchema: GetAiProfilesOutputJsonSchema,
        annotations: {
          title: "Get AI Profiles",
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "get_ai_skills",
        title: "Get AI Skills",
        description: "Get the skills of an instructions room, or of all instructions rooms linked to an AI project. A skill ID is the ID of its Markdown file, which get_file_info and download_file_as_text accept.",
        inputSchema: GetAiSkillsInputJsonSchema,
        outputSchema: GetAiSkillsOutputJsonSchema,
        annotations: {
          title: "Get AI Skills",
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
      {
        name: "retry_vectorization",
        title: "Retry Vectorization",
        description: "Vectorize files of a knowledge room again, such as files whose vectorizationStatus is 2 (failed). Only room managers can do it, and only for files whose security.Vectorization is true. Files that are already vectorized or being vectorized are skipped without an error. Check the progress with the vectorizationStatus field of get_file_info.",
        inputSchema: RetryVectorizationInputJsonSchema,
        annotations: {
          title: "Retry Vectorization",
          readOnlyHint: false,
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
        title: "Get All People",
        description: "Get all people.",
        inputSchema: GetAllPeopleInputJsonSchema,
        outputSchema: GetAllPeopleOutputJsonSchema,
        annotations: {
          title: "Get All People",
          readOnlyHint: true,
          destructiveHint: false,
          openWorldHint: false,
        },
      },
    ],
  },
] as mcp.Toolset[]

const regularTools = (() => {
  const a: mcp.Tool[] = []

  for (const t of regularToolsets) {
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
    create_ai_room: this.handleCreateAiRoom.bind(this),
    create_folder: this.handleCreateFolder.bind(this),
    create_room: this.handleCreateRoom.bind(this),
    delete_ai_room: this.handleDeleteAiRoom.bind(this),
    delete_file: this.handleDeleteFile.bind(this),
    delete_folder: this.handleDeleteFolder.bind(this),
    download_file_as_text: this.handleDownloadFileAsText.bind(this),
    get_ai_config: this.handleGetAiConfig.bind(this),
    get_ai_profiles: this.handleGetAiProfiles.bind(this),
    get_ai_project_model: this.handleGetAiProjectModel.bind(this),
    get_ai_project_sources: this.handleGetAiProjectSources.bind(this),
    get_ai_rooms_folder: this.handleGetAiRoomsFolder.bind(this),
    get_ai_skills: this.handleGetAiSkills.bind(this),
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
    link_ai_project_sources: this.handleLinkAiProjectSources.bind(this),
    move_batch_items: this.handleMoveBatchItems.bind(this),
    rename_folder: this.handleRenameFolder.bind(this),
    retry_vectorization: this.handleRetryVectorization.bind(this),
    run_builder_script: this.handleRunBuilderScript.bind(this),
    set_ai_project_model: this.handleSetAiProjectModel.bind(this),
    set_room_security: this.handleSetRoomSecurity.bind(this),
    unlink_ai_project_sources: this.handleUnlinkAiProjectSources.bind(this),
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

    for (const x of regularToolsets) {
      const y: mcp.Toolset = {
        name: x.name,
        description: x.description,
        tools: [],
      }

      for (const a of x.tools) {
        for (const b of config.tools) {
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

    for (const x of Object.keys(this.callRegularToolHandlers)) {
      let f = false

      for (const y of this.regularTools) {
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
    const r: mcp.Router = {
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
    const h = this.callMetaToolHandlers[req.params.name]
    if (!h) {
      return fromError(new Error(`Tool ${req.params.name} not found`))
    }
    return await h(req)
  }

  private async handleRegularCallTool(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const h = this.callRegularToolHandlers[req.params.name]
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
    const pr = CallToolInputSchema.safeParse(req.params.arguments)
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
    const pr = GetToolInputSchemaInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let i: mcp.ToolInputSchema | undefined

    for (const x of this.regularToolsets) {
      for (const y of x.tools) {
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
    const pr = GetToolInputSchemaInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let o: mcp.ToolOutputSchema | undefined

    for (const x of this.regularToolsets) {
      for (const y of x.tools) {
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
    const pr = ListToolsInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    let s: mcp.Toolset | undefined

    for (const t of this.regularToolsets) {
      if (t.name === pr.data.toolset) {
        s = t
        break
      }
    }

    if (!s) {
      return fromError(new Error(`Toolset '${pr.data.toolset}' not found.`))
    }

    const summaries: mcp.ToolSummary[] = []

    for (const t of s.tools) {
      const s: mcp.ToolSummary = {
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
    const summaries: mcp.ToolSummary[] = []

    for (const t of this.regularToolsets) {
      const s: mcp.ToolSummary = {
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
    const pr = ArchiveRoomInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const ar = await this.client.files.archiveRoom(pr.data.roomId, {})
    if (ar.err) {
      return fromError(new Error("Archiving room.", {cause: ar.err}))
    }

    const [ad] = ar.v

    const rr = await this.resolver.resolve(ad)
    if (rr.err) {
      return fromError(new Error("Resolving archive room operations.", {cause: rr.err}))
    }

    return fromString("Room archived.")
  }

  private async handleCopyBatchItems(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = CopyBatchItemsInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const co: core.CopyBatchItemsOptions = {
      // @ts-expect-error See the type above for the reason.
      folderIds: pr.data.folderIds,
      // @ts-expect-error See the type above for the reason.
      fileIds: pr.data.fileIds,
      // @ts-expect-error See the type above for the reason.
      destFolderId: pr.data.destFolderId,
      conflictResolveType: 2,
      deleteAfter: false,
    }

    const cr = await this.client.files.copyBatchItems(co)
    if (cr.err) {
      return fromError(new Error("Copying batch items.", {cause: cr.err}))
    }

    const [cd] = cr.v

    const rr = await this.resolver.resolve(...cd)
    if (rr.err) {
      return fromError(new Error("Resolving copy batch items operations.", {cause: rr.err}))
    }

    return fromString("Batch items copied.")
  }

  private async handleCreateFolder(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = CreateFolderInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const co: core.CreateFolderOptions = {
      title: pr.data.title,
    }

    const cr = await this.client.files.createFolder(pr.data.parentId, co, pr.data.filters)
    if (cr.err) {
      return fromError(new Error("Creating folder.", {cause: cr.err}))
    }

    const [, res] = cr.v

    return await fromResponse(res, CreateFolderOutputJsonSchema)
  }

  private async handleCreateRoom(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = CreateRoomInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const co: core.CreateRoomOptions = {
      title: pr.data.title,
      roomType: pr.data.roomType,
    }

    const cr = await this.client.files.createRoom(co, pr.data.filters)
    if (cr.err) {
      return fromError(new Error("Creating room.", {cause: cr.err}))
    }

    const [, res] = cr.v

    return await fromResponse(res, CreateRoomOutputJsonSchema)
  }

  private async handleDeleteFile(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = DeleteFileInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const tr = await this.client.files.getTrashFolder()
    if (tr.err) {
      return fromError(new Error("Getting trash folder.", {cause: tr.err}))
    }

    const [td] = tr.v

    if (!td.current) {
      return fromError(new Error("Trash folder is not defined."))
    }

    if (!td.current.id) {
      return fromError(new Error("Trash folder ID is not defined."))
    }

    const fr = await this.client.files.getFileInfo(pr.data.fileId)
    if (fr.err) {
      return fromError(new Error("Getting file info.", {cause: fr.err}))
    }

    const [gd] = fr.v

    if (!gd.folderId) {
      return fromError(new Error("File folder ID is not defined."))
    }

    if (gd.folderId === td.current.id) {
      return fromString("File is already in the trash folder.")
    }

    const dp: core.DeleteFileOptions = {
      deleteAfter: false,
      immediately: false,
    }

    const dr = await this.client.files.deleteFile(pr.data.fileId, dp)
    if (dr.err) {
      return fromError(new Error("Deleting file.", {cause: dr.err}))
    }

    const [dd] = dr.v

    const rr = await this.resolver.resolve(...dd)
    if (rr.err) {
      return fromError(new Error("Resolving delete file operations.", {cause: rr.err}))
    }

    return fromString("File deleted.")
  }

  private async handleDeleteFolder(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = DeleteFolderInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const dp: core.DeleteFolderOptions = {
      deleteAfter: false,
      immediately: false,
    }

    const dr = await this.client.files.deleteFolder(pr.data.folderId, dp)
    if (dr.err) {
      return fromError(new Error("Deleting folder.", {cause: dr.err}))
    }

    const [dd] = dr.v

    const rr = await this.resolver.resolve(...dd)
    if (rr.err) {
      return fromError(new Error("Resolving delete folder operations.", {cause: rr.err}))
    }

    return fromString("Folder deleted.")
  }

  private async handleDownloadFileAsText(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = DownloadFileAsTextInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const ir = await this.client.files.getFileInfo(pr.data.fileId)
    if (ir.err) {
      return fromError(new Error("Getting file info.", {cause: ir.err}))
    }

    const [id] = ir.v

    if (!id.fileExst) {
      return fromError(new Error("File extension is not defined."))
    }

    let tx: string

    if (plainTextExts.has(id.fileExst.toLowerCase())) {
      const dr = await this.downloadPlainText(pr.data.fileId)
      if (dr.err) {
        return fromError(dr.err)
      }
      tx = dr.v
    } else {
      const dr = await this.downloadConvertedText(pr.data.fileId, id.fileExst)
      if (dr.err) {
        return fromError(dr.err)
      }
      tx = dr.v
    }

    const of = pr.data.offset ?? 0
    const li = pr.data.limit ?? downloadTextDefaultLimit
    const en = of + li

    if (of === 0 && tx.length <= li) {
      return fromString(tx)
    }

    if (of >= tx.length) {
      return fromError(new Error(`Offset ${of} is out of range, the text has ${tx.length} characters.`))
    }

    const ch = tx.slice(of, en)

    if (en >= tx.length) {
      return fromString(ch)
    }

    return fromString(`${ch}\n\n[Truncated: showing ${ch.length} characters starting at offset ${of} of ${tx.length} in total. To read the rest, call this tool again with offset=${en}.]`)
  }

  /**
   * Downloads a file in a plain text format as it is, so the markup, such as
   * the frontmatter of a skill, is kept.
   */
  private async downloadPlainText(fileId: number): Promise<r.Result<string, Error>> {
    const dr = await this.client.files.downloadFile(fileId)
    if (dr.err) {
      return r.error(new Error("Downloading file.", {cause: dr.err}))
    }

    const tt = await r.safeAsync(dr.v.response.text.bind(dr.v.response))
    if (tt.err) {
      return r.error(new Error("Converting response to text.", {cause: tt.err}))
    }

    return r.ok(tt.v)
  }

  /**
   * Converts a document, a spreadsheet, a presentation or a PDF file to plain
   * text on the portal and downloads the result.
   */
  private async downloadConvertedText(fileId: number, fileExst: string): Promise<r.Result<string, Error>> {
    const sr = await this.client.files.getFilesSettings()
    if (sr.err) {
      return r.error(new Error("Getting files settings.", {cause: sr.err}))
    }

    const [sd] = sr.v

    if (!sd.extsConvertible) {
      return r.error(new Error("Convertible file extensions are not defined."))
    }

    const fr = sd.extsConvertible[fileExst]

    if (!fr) {
      return r.error(new Error(`File extension ${fileExst} is not convertible.`))
    }

    let ex: string | undefined

    for (const e of fr) {
      if (e === ".csv" || e === ".txt") {
        ex = e
        break
      }
    }

    if (!ex) {
      return r.error(new Error(`No convertible extension found for ${fileExst}.`))
    }

    const bo: core.BulkDownloadOptions = {
      fileConvertIds: [{key: fileId, value: ex}],
    }

    const br = await this.client.files.bulkDownload(bo)
    if (br.err) {
      return r.error(new Error("Making bulk download.", {cause: br.err}))
    }

    const [bd] = br.v

    const rr = await this.resolver.resolve(...bd)
    if (rr.err) {
      return r.error(new Error("Resolving bulk download operations.", {cause: rr.err}))
    }

    if (rr.v.operations.length === 0) {
      return r.error(new Error("No resolved operations."))
    }

    if (rr.v.operations.length > 1) {
      return r.error(new Error(`Expected 1 resolved operation, got ${rr.v.operations.length}.`))
    }

    const [rd] = rr.v.operations

    if (rd.url === undefined) {
      return r.error(new Error("Resolved operation has no URL."))
    }

    const dr = this.client.createRequest("GET", rd.url)
    if (dr.err) {
      return r.error(new Error("Creating download request.", {cause: dr.err}))
    }

    const hr = r.safeSync(dr.v.headers.set.bind(dr.v.headers), "Accept", "text/plain")
    if (hr.err) {
      return r.error(new Error("Setting header.", {cause: hr.err}))
    }

    const tr = await this.client.bareFetch(dr.v)
    if (tr.err) {
      return r.error(new Error("Downloading file.", {cause: tr.err}))
    }

    const tt = await r.safeAsync(tr.v.text.bind(tr.v))
    if (tt.err) {
      return r.error(new Error("Converting response to text.", {cause: tt.err}))
    }

    return r.ok(tt.v)
  }

  private async handleGetAllPeople(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = GetAllPeopleInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const gr = await this.client.people.getFullByFilter(pr.data.filters)
    if (gr.err) {
      return fromError(new Error("Getting people.", {cause: gr.err}))
    }

    const [, res] = gr.v

    return await fromResponse(res, GetAllPeopleOutputJsonSchema)
  }

  private async handleGetFileInfo(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = GetFileInfoInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const gr = await this.client.files.getFileInfo(pr.data.fileId, pr.data.filters)
    if (gr.err) {
      return fromError(new Error("Getting file info.", {cause: gr.err}))
    }

    const [, res] = gr.v

    return await fromResponse(res, GetFileInfoOutputJsonSchema)
  }

  private async handleGetFolderContent(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = GetFolderContentInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const gr = await this.client.files.getFolder(pr.data.folderId, pr.data.filters)
    if (gr.err) {
      return fromError(new Error("Getting folder.", {cause: gr.err}))
    }

    const [, res] = gr.v

    return await fromResponse(res, GetFolderContentOutputJsonSchema)
  }

  private async handleGetFolderInfo(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = GetFolderInfoInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const gr = await this.client.files.getFolderInfo(pr.data.folderId, pr.data.filters)
    if (gr.err) {
      return fromError(new Error("Getting folder info.", {cause: gr.err}))
    }

    const [, res] = gr.v

    return await fromResponse(res, GetFolderInfoOutputJsonSchema)
  }

  private async handleGetMyFolder(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = GetMyFolderInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const gr = await this.client.files.getMyFolder(pr.data.filters)
    if (gr.err) {
      return fromError(new Error("Getting my folder.", {cause: gr.err}))
    }

    const [, res] = gr.v

    return await fromResponse(res, GetMyFolderOutputJsonSchema)
  }

  private async handleGetOfficeApiReference(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = GetOfficeApiReferenceInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    if (pr.data.method !== undefined && pr.data.class === undefined) {
      return fromError(new Error("The method has to be given together with its class."))
    }

    const ir = await this.officeApiReference.index(pr.data.editor)
    if (ir.err) {
      return fromError(new Error("Getting reference index.", {cause: ir.err}))
    }

    const a = ir.v

    if (pr.data.class !== undefined) {
      let n = pr.data.class
      let k: officeApi.ReferenceEntryKind[] = ["class", "enumeration"]

      if (pr.data.method !== undefined) {
        n = `${pr.data.class}.${pr.data.method}`
        k = ["method"]
      }

      const en = officeApi.findEntry(a, n, k)

      if (!en) {
        return fromError(new Error(officeApi.notFoundMessage(a, pr.data.editor, pr.data.class, pr.data.method)))
      }

      const pg = await this.officeApiReference.page(en)
      if (pg.err) {
        return fromError(new Error("Getting reference page.", {cause: pg.err}))
      }

      return fromString(pg.v)
    }

    if (pr.data.query !== undefined) {
      const f = officeApi.searchEntries(a, pr.data.query)

      if (f.length === 0) {
        return fromString(`Nothing in the ${pr.data.editor} API matches "${pr.data.query}". Try other words, or call the tool without query for the list of classes.`)
      }

      const m = 50
      let t = ""

      for (const e of f.slice(0, m)) {
        t += `- ${e.name} (${e.kind}): ${e.description}\n`
      }

      if (f.length > m) {
        t += `\n${f.length - m} more matches are not shown; add words to the query to narrow it.\n`
      }

      return fromString(t.trim())
    }

    const ov = a.find((e) => e.kind === "overview")

    let t = ""

    if (ov) {
      const pg = await this.officeApiReference.page(ov)
      if (pg.err) {
        return fromError(new Error("Getting reference overview.", {cause: pg.err}))
      }

      t += `${pg.v}\n\n`
    }

    t += "## Classes\n\n"

    for (const e of a) {
      if (e.kind === "class") {
        t += `- ${e.name}: ${e.description}\n`
      }
    }

    t += "\n## Enumerations\n\n"

    const en: string[] = []

    for (const e of a) {
      if (e.kind === "enumeration") {
        en.push(e.name)
      }
    }

    t += `${en.join(", ")}\n\n`
    t += "Pass class to get the methods of a class or the values of an enumeration, class and method to get a method, and query to search."

    return fromString(t)
  }

  private async handleGetRoomAccessLevels(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = GetRoomAccessLevelsInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const gr = await this.client.files.getRoomInfo(pr.data.roomId)
    if (gr.err) {
      return fromError(new Error("Getting room info.", {cause: gr.err}))
    }

    const [gd] = gr.v

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
    case 10:
      sh = InstructionsRoomInvitationAccessSchema
      break
    case 11:
      sh = KnowledgeRoomInvitationAccessSchema
      break
    case 12:
      sh = AiProjectInvitationAccessSchema
      break
    default:
      sh = RoomInvitationAccessSchema
      break
    }

    return fromObject(z.toJSONSchema(sh))
  }

  private async handleGetRoomInfo(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = GetRoomInfoInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const gr = await this.client.files.getRoomInfo(pr.data.roomId, pr.data.filters)
    if (gr.err) {
      return fromError(new Error("Getting room info.", {cause: gr.err}))
    }

    const [, res] = gr.v

    return await fromResponse(res, GetRoomInfoOutputJsonSchema)
  }

  private async handleGetRoomSecurityInfo(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = GetRoomSecurityInfoInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const gr = await this.client.files.getRoomSecurityInfo(pr.data.roomId, pr.data.filters)
    if (gr.err) {
      return fromError(new Error("Getting room security info.", {cause: gr.err}))
    }

    const [, res] = gr.v

    return await fromResponse(res, GetRoomSecurityInfoOutputJsonSchema)
  }

  private handleGetRoomTypes(): types.CallToolResult {
    return fromObject(z.toJSONSchema(core.RoomTypeSchema))
  }

  private async handleGetRoomsFolder(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = GetRoomsFolderInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const gr = await this.client.files.getRoomsFolder(pr.data.filters)
    if (gr.err) {
      return fromError(new Error("Getting rooms folder.", {cause: gr.err}))
    }

    const [, res] = gr.v

    return await fromResponse(res, GetRoomsFolderOutputJsonSchema)
  }

  private async handleMoveBatchItems(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = MoveBatchItemsInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const mo: core.MoveBatchItemsOptions = {
      // @ts-expect-error See the type above for the reason.
      folderIds: pr.data.folderIds,
      // @ts-expect-error See the type above for the reason.
      fileIds: pr.data.fileIds,
      // @ts-expect-error See the type above for the reason.
      destFolderId: pr.data.destFolderId,
      conflictResolveType: 2,
      deleteAfter: false,
    }

    const mr = await this.client.files.moveBatchItems(mo)
    if (mr.err) {
      return fromError(new Error("Moving batch items.", {cause: mr.err}))
    }

    const [md] = mr.v

    const rr = await this.resolver.resolve(...md)
    if (rr.err) {
      return fromError(new Error("Resolving move batch items operations.", {cause: rr.err}))
    }

    return fromString("Batch items moved.")
  }

  private async handleRenameFolder(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = RenameFolderInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const ro: core.RenameFolderOptions = {
      title: pr.data.title,
    }

    const rr = await this.client.files.renameFolder(pr.data.folderId, ro, pr.data.filters)
    if (rr.err) {
      return fromError(new Error("Renaming folder.", {cause: rr.err}))
    }

    const [, res] = rr.v

    return await fromResponse(res, RenameFolderOutputJsonSchema)
  }

  private async handleRunBuilderScript(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = RunBuilderScriptInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const ro: core.RunBuilderScriptOptions = {
      script: pr.data.script,
      folderId: pr.data.folderId,
      outputs: pr.data.outputs,
      argument: pr.data.argument,
    }

    const it = await this.fileOperationCaller.call(() => this.client.files.runBuilderScript(ro))

    for await (const _ of it) {
      // Wait for the operation to finish.
    }

    const rr = it.result()
    if (rr.err) {
      const h = builderErrorHint(rr.err)
      if (h) {
        return fromError(new Error("Running builder script.", {cause: new AggregateError([rr.err, new Error(h)])}))
      }
      return fromError(new Error("Running builder script.", {cause: rr.err}))
    }

    // The operation may end without a single status having been received.
    if (!rr.v) {
      return fromError(new Error("Builder script operation has no result."))
    }

    const files: unknown[] = []

    if (Array.isArray(rr.v.files)) {
      for (const f of rr.v.files) {
        files.push(pickFields(f, pr.data.filters.fields))
      }
    }

    return fromObject({files}, RunBuilderScriptOutputJsonSchema)
  }

  private async handleSetRoomSecurity(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = SetRoomSecurityInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const so: core.SetRoomSecurityOptions = {
      invitations: pr.data.invitations,
      notify: pr.data.notify,
      message: pr.data.message,
    }

    const sr = await this.client.files.setRoomSecurity(pr.data.roomId, so, pr.data.filters)
    if (sr.err) {
      return fromError(new Error("Setting room security.", {cause: sr.err}))
    }

    const [, res] = sr.v

    return await fromResponse(res, SetRoomSecurityOutputJsonSchema)
  }

  private async handleUpdateFile(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = UpdateFileInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const uo: core.UpdateFileOptions = {
      title: pr.data.title,
    }

    const ur = await this.client.files.updateFile(pr.data.fileId, uo)
    if (ur.err) {
      return fromError(new Error("Updating file.", {cause: ur.err}))
    }

    const [, res] = ur.v

    return await fromResponse(res, UpdateFileOutputJsonSchema)
  }

  private async handleUpdateRoom(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = UpdateRoomInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const uo: core.UpdateRoomOptions = {
      title: pr.data.title,
    }

    const ur = await this.client.files.updateRoom(pr.data.roomId, uo, pr.data.filters)
    if (ur.err) {
      return fromError(new Error("Updating room.", {cause: ur.err}))
    }

    const [, res] = ur.v

    return await fromResponse(res, UpdateRoomOutputJsonSchema)
  }

  private async handleUploadFile(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = UploadFileInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const fp = path.parse(pr.data.filename)

    if (!fp.ext) {
      return fromError(new Error("File extension is missing in the filename."))
    }

    const te = new TextEncoder()

    const buf = te.encode(pr.data.content)

    const so: core.CreateUploadSessionOptions = {
      fileName: pr.data.filename,
      fileSize: buf.length,
      createOn: new Date().toISOString(),
      // The portal saves the content as a new version of the file with the same
      // name only when createNewIfExist is false.
      createNewIfExist: !pr.data.overwrite,
    }

    const sr = await this.client.files.createUploadSession(pr.data.parentId, so)
    if (sr.err) {
      return fromError(new Error("Creating upload session.", {cause: sr.err}))
    }

    const [sd] = sr.v

    if (sd.id === undefined) {
      return fromError(new Error("Upload session ID is not defined."))
    }

    const ur = await this.uploader.upload(sd.id, buf)
    if (ur.err) {
      return fromError(new Error("Uploading file.", {cause: ur.err}))
    }

    const [ud, res] = ur.v

    const rs = await fromResponse(res)

    if (pr.data.overwrite && !rs.isError) {
      // The portal does not overwrite a file that is locked, open in the editor
      // or that the user cannot edit, and silently uploads a new file with
      // another name instead.
      const up = UploadedFileSchema.safeParse(ud)
      if (up.success && up.data.title !== undefined && up.data.title !== pr.data.filename) {
        rs.content.push({
          type: "text",
          text: `The portal did not overwrite ${pr.data.filename} and uploaded a new file named ${up.data.title} instead. The file may be locked, open in the editor, or the user may lack the rights to edit it.`,
        })
      }
    }

    return rs
  }

  //
  // AI rooms
  //

  private async handleCreateAiRoom(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = CreateAiRoomInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const co: core.CreateAiRoomOptions = {
      title: pr.data.title,
      roomType: pr.data.roomType,
      tags: pr.data.tags,
      color: pr.data.color,
    }

    const cr = await this.client.files.createAiRoom(co, pr.data.filters)
    if (cr.err) {
      return fromAiError("Creating AI room.", cr.err, {
        403: "The portal refused to create the room. A knowledge room can be created only while vectorization is enabled, and no AI room can be created while AI is turned off; get_ai_config shows both. Accounts of the User and Guest types cannot create AI rooms.",
      })
    }

    const [, res] = cr.v

    return await fromResponse(res, CreateAiRoomOutputJsonSchema)
  }

  private async handleDeleteAiRoom(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = DeleteAiRoomInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const gr = await this.client.files.getRoomInfo(pr.data.roomId)
    if (gr.err) {
      return fromAiError("Getting room info.", gr.err, {403: aiForbiddenHint})
    }

    const [gd] = gr.v

    // Deleting a room is permanent, so do not let this tool delete the rooms
    // that are meant to be archived first.
    if (gd.roomType !== 10 && gd.roomType !== 11 && gd.roomType !== 12) {
      return fromError(new Error(`Room ${pr.data.roomId} is not an AI room. Archive it with archive_room instead.`))
    }

    const dr = await this.client.files.deleteRoom(pr.data.roomId, {deleteAfter: false})
    if (dr.err) {
      return fromAiError("Deleting AI room.", dr.err, {403: aiForbiddenHint})
    }

    const [dd] = dr.v

    const rr = await this.resolver.resolve(dd)
    if (rr.err) {
      return fromError(new Error("Resolving delete room operations.", {cause: rr.err}))
    }

    return fromString("Room deleted.")
  }

  private async handleGetAiConfig(): Promise<types.CallToolResult> {
    const gr = await this.client.ai.getConfig()
    if (gr.err) {
      return fromError(new Error("Getting AI config.", {cause: gr.err}))
    }

    const [gd] = gr.v

    const o: z.output<typeof GetAiConfigOutputSchema> = {
      aiReady: gd.aiReady ?? false,
      vectorizationEnabled: gd.vectorizationEnabled ?? false,
    }

    return fromObject(o, GetAiConfigOutputJsonSchema)
  }

  private async handleGetAiProfiles(): Promise<types.CallToolResult> {
    const gr = await this.client.ai.getProfiles()
    if (gr.err) {
      return fromAiError("Getting AI profiles.", gr.err, {403: aiForbiddenHint})
    }

    const [gd] = gr.v

    const o: z.output<typeof GetAiProfilesOutputSchema> = {
      profiles: [],
    }

    for (const p of gd) {
      const c = p.capabilities ?? 0

      // A profile without capabilities predates them and is treated as a chat
      // model, as the portal does when it sets the model of a project.
      if (c !== 0 && (c & 0x1) === 0) {
        continue
      }

      o.profiles.push({
        id: p.id,
        name: p.name,
        providerType: p.providerType,
        modelId: p.modelId,
        tools: (c & 0x100) !== 0 || p.canUseTool === true,
        vision: (c & 0x80) !== 0,
      })
    }

    return fromObject(o, GetAiProfilesOutputJsonSchema)
  }

  private async handleGetAiProjectModel(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = GetAiProjectModelInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const gr = await this.client.files.getAiProjectModel(pr.data.roomId)
    if (gr.err) {
      return fromAiError("Getting AI project model.", gr.err, {403: aiForbiddenHint, 404: aiNotFoundHint})
    }

    const [, res] = gr.v

    return await fromResponse(res, GetAiProjectModelOutputJsonSchema)
  }

  private async handleGetAiProjectSources(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = GetAiProjectSourcesInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const gr = await this.client.files.getAiProjectSources(pr.data.roomId)
    if (gr.err) {
      return fromAiError("Getting AI project sources.", gr.err, {403: aiForbiddenHint, 404: aiNotFoundHint})
    }

    const [, res] = gr.v

    return await fromResponse(res, GetAiProjectSourcesOutputJsonSchema)
  }

  private async handleGetAiRoomsFolder(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = GetAiRoomsFolderInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const gr = await this.client.files.getAiRoomsFolder(pr.data.filters)
    if (gr.err) {
      return fromAiError("Getting AI rooms folder.", gr.err, {403: aiForbiddenHint})
    }

    const [, res] = gr.v

    return await fromResponse(res, GetAiRoomsFolderOutputJsonSchema)
  }

  private async handleGetAiSkills(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = GetAiSkillsInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const gr = await this.client.files.getAiRoomSkills(pr.data.roomId)
    if (gr.err) {
      return fromAiError("Getting AI skills.", gr.err, {403: aiForbiddenHint, 404: aiNotFoundHint})
    }

    const [, res] = gr.v

    return await fromResponse(res, GetAiSkillsOutputJsonSchema)
  }

  private async handleLinkAiProjectSources(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = AiProjectSourcesInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const lr = await this.client.files.linkAiProjectSources(pr.data.roomId, {roomIds: pr.data.roomIds})
    if (lr.err) {
      return fromAiError("Linking AI project sources.", lr.err, {403: aiForbiddenHint, 404: aiNotFoundHint})
    }

    return fromString("Rooms linked.")
  }

  private async handleRetryVectorization(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = RetryVectorizationInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const sr = await this.client.ai.startVectorization({files: pr.data.fileIds})
    if (sr.err) {
      return fromAiError("Retrying vectorization.", sr.err, {
        403: "The user may not vectorize one of the files. Only room managers can, only for files of knowledge rooms that have been queued for vectorization before and whose security.Vectorization is true, and only while vectorization is enabled, which get_ai_config shows.",
        404: "One of the files does not exist.",
      })
    }

    return fromString("Vectorization requested. Files that are already vectorized or being vectorized are skipped; check vectorizationStatus with get_file_info.")
  }

  private async handleSetAiProjectModel(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = SetAiProjectModelInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const ur = await this.client.files.updateAiProjectModel(pr.data.roomId, {profileId: pr.data.profileId})
    if (ur.err) {
      return fromAiError("Setting AI project model.", ur.err, {
        400: "The profile does not exist or is not a chat model. Pick a profile from get_ai_profiles.",
        403: aiForbiddenHint,
        404: aiNotFoundHint,
      })
    }

    const [, res] = ur.v

    return await fromResponse(res, SetAiProjectModelOutputJsonSchema)
  }

  private async handleUnlinkAiProjectSources(req: types.CallToolRequest): Promise<types.CallToolResult> {
    const pr = AiProjectSourcesInputSchema.safeParse(req.params.arguments)
    if (!pr.success) {
      return fromError(new Error("Parsing input.", {cause: pr.error}))
    }

    const ur = await this.client.files.unlinkAiProjectSources(pr.data.roomId, {roomIds: pr.data.roomIds})
    if (ur.err) {
      return fromAiError("Unlinking AI project sources.", ur.err, {403: aiForbiddenHint, 404: aiNotFoundHint})
    }

    return fromString("Rooms unlinked.")
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

  const o: Record<string, unknown> = {}

  for (const f of fields) {
    const k = f.split(".")

    // Resolves the value before writing anything, so that a missing leaf does
    // not leave empty intermediate objects behind.
    let s: unknown = v
    let ok = true

    for (const p of k) {
      if (typeof s !== "object" || s === null || !(p in s)) {
        ok = false
        break
      }

      s = (s as Record<string, unknown>)[p]
    }

    if (!ok) {
      continue
    }

    let d = o

    for (const p of k.slice(0, -1)) {
      if (typeof d[p] !== "object" || d[p] === null) {
        d[p] = {}
      }

      d = d[p] as Record<string, unknown>
    }

    d[k[k.length - 1]] = s
  }

  return o
}

const builderTimeoutHint = "The script did not finish within the time the server waits for a file operation, so the server stopped waiting and terminated it; a terminated script saves no files. Make the script do less, or split the work across several scripts, then run it again."

const builderTerminateHint = "The server stopped waiting for the script but could not terminate it, so the script may still be running, may save files later and may keep the portal from running the next script until it ends. Wait a while and check the target folder for the saved files before running the script again."

// Document Builder reports no details on a failed script, only one of the
// codes from
// https://api.onlyoffice.com/docs/docs-api/additional-api/document-builder-api#possible-error-codes-and-their-description,
// which the portal puts at the end of the operation error as "error -3".
const builderErrorHints: Record<string, string> = {
  "-1": "Document Builder error -1 (unknown error): the script failed for a reason Document Builder does not report.",
  "-2": "Document Builder error -2 (generation timeout): the script ran too long. Make it do less, or split the work across several scripts.",
  "-3": "Document Builder error -3 (document generation error): the script threw. Document Builder reports neither the message nor the line, so the cause is one of: a syntax error, a call to a method that does not exist in this version of the Office JavaScript API, wrong arguments, or an explicit throw. Check every class and method the script uses with get_office_api_reference, fix the script and run it again; if the cause is still unclear, run a shorter part of the script to find the failing line.",
  "-4": "Document Builder error -4 (download error): the document opened with builder.OpenFile could not be downloaded. Check that the file ID is right and the file is accessible.",
  "-6": "Document Builder error -6 (result database error): a server-side failure unrelated to the script. Try again later.",
  "-8": "Document Builder error -8 (invalid token): the portal and ONLYOFFICE Docs are misconfigured, which no change to the script fixes. Tell the user to contact the portal administrator.",
}

function builderErrorHint(err: unknown): string | undefined {
  if (err instanceof DOMException && err.name === "TimeoutError") {
    return builderTimeoutHint
  }

  if (err instanceof AggregateError) {
    // A failed termination outweighs the reason the script was abandoned, whose
    // hint would claim the script saves nothing.
    for (const e of err.errors) {
      if (e instanceof Error && e.message === "Terminating operation") {
        return builderTerminateHint
      }
    }

    for (const e of err.errors) {
      const h = builderErrorHint(e)
      if (h) {
        return h
      }
    }
  }

  if (err instanceof Error) {
    const m = /\berror (-\d+)\)\s*$/.exec(err.message)
    if (m && Object.hasOwn(builderErrorHints, m[1])) {
      return builderErrorHints[m[1]]
    }

    return builderErrorHint(err.cause)
  }

  return
}

const aiForbiddenHint = "The portal refused the call. AI may be turned off on the portal, which get_ai_config shows, or the user may lack the rights for the room."

const aiNotFoundHint = "The room was not found, or it is not of the type the tool expects. Find the AI rooms with get_ai_rooms_folder."

// The AI service reports no details on most errors, only the status, so the
// hints explain what the status means for each tool.
function fromAiError(m: string, err: Error, hints: Partial<Record<number, string>>): types.CallToolResult {
  let e: unknown = err
  while (e instanceof Error) {
    if (e instanceof core.ResponseError) {
      const h = hints[e.response.response.status]
      if (h) {
        return fromError(new Error(m, {cause: new AggregateError([err, new Error(h)])}))
      }
      break
    }
    e = e.cause
  }
  return fromError(new Error(m, {cause: err}))
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
  const h = res.response.headers.get("Content-Type")
  if (h === null) {
    return fromError(new Error("Content-Type header is missing"))
  }

  if (h.startsWith("application/json")) {
    const j = await r.safeAsync(res.response.json.bind(res.response))
    if (j.err) {
      return fromError(new Error("Parsing json response", {cause: j.err}))
    }

    const t = r.safeSync(JSON.stringify, j.v, undefined, 2)
    if (t.err) {
      return fromError(new Error("Stringifying json value", {cause: t.err}))
    }

    const c: types.CallToolResult = {
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
    const t = await r.safeAsync(res.response.text.bind(res.response))
    if (t.err) {
      return fromError(new Error("Parsing text response", {cause: t.err}))
    }

    const c: types.CallToolResult = {
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
  const t = r.safeSync(JSON.stringify, o, undefined, 2)
  if (t.err) {
    return fromError(new Error("Stringifying object value", {cause: t.err}))
  }

  const c: types.CallToolResult = {
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
