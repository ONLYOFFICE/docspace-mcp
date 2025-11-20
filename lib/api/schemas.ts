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
 * @mergeModuleWith api
 */

import * as z from "zod"
import {numberUnionToEnum, stringUnionToEnum, wrapUnion} from "../util/zod.ts"

/**
 * {@link https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/builtin-types/reference-types/#the-object-type | .NET Reference}
 */
export const TypeObjectSchema = z.union([
	z.string(),
	z.number(),
	z.boolean(),
	z.null(),
	z.array(z.unknown()),
	z.object({}).passthrough(),
])

/**
 * {@link https://learn.microsoft.com/en-us/dotnet/api/system.text.json.jsonelement/?view=net-9.0 | .NET Reference}
 */
export const JsonElementSchema = z.union([z.string(), z.number()])

export const NumericSortOrderSchema = z.union([
	z.literal(0).describe("Ascending order"),
	z.literal(1).describe("Descending order"),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/common/ASC.Api.Core/Middleware/CommonApiResponse.cs/#L31 | DocSpace Reference}
 */
export const CommonApiResponseSchema = z.object({
	status: z.number().describe("The status of the API response."),
	statusCode: z.number().describe("The HTTP status code of the API response."),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/common/ASC.Api.Core/Middleware/CommonApiResponse.cs/#L128 | DocSpace Reference}
 */
export const CommonApiErrorSchema = z.object({
	message: z.string(),
	type: z.string(),
	stack: z.string(),
	hresult: z.number(),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/common/ASC.Api.Core/Middleware/CommonApiResponse.cs/#L46 | DocSpace Reference}
 */
export const ErrorApiResponseSchema = CommonApiResponseSchema.extend({
	error: CommonApiErrorSchema,
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/common/ASC.Api.Core/Middleware/CommonApiResponse.cs/#L153 | DocSpace Reference}
 */
export const LinkSchema = z.object({
	href: z.string(),
	action: z.string(),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/common/ASC.Api.Core/Middleware/CommonApiResponse.cs/#L57 | DocSpace Reference}
 */
export const SuccessApiResponseSchema = CommonApiResponseSchema.extend({
	response: TypeObjectSchema.describe("The response data of the API request."),
	count: z.number().optional().describe("The number of items in the response."),
	total: z.number().optional().describe("The total number of items available."),
	links: z.array(LinkSchema).describe("The links related to the response."),
})

// /**
//  * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/common/ASC.Api.Core/Model/Contact.cs/#L32 | DocSpace Reference}
//  */
// export const ContentFieldSchema = z.union([
// 	z.literal("type").describe("The contact type."),
// 	z.literal("value").describe("The contact value."),
// ])

// /**
//  * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/common/ASC.Api.Core/Model/GroupSummaryDto.cs/#L34 | DocSpace Reference}
//  */
// export const GroupSummaryDtoFieldSchema = z.union([
// 	z.literal("id").describe("The group ID."),
// 	z.literal("name").describe("The group name."),
// 	z.literal("manager").describe("The group manager."),
// ])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/common/ASC.Api.Core/Model/EmailInvitationDto.cs/#L36 | DocSpace Reference}
 */
export const EmailInvitationDtoSchema = z.object({
	email: z.string().optional(),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.2.1-server/common/ASC.Api.Core/Model/EmployeeDto.cs/#L34 | DocSpace Reference}
 */
export const EmployeeDtoSchema = z.
	object({
		id: z.string().optional().describe("The user ID."),
		displayName: z.string().optional().describe("The user display name."),
		isAnonim: z.boolean().optional().describe("Specifies if the user is anonymous or not."),
	}).
	passthrough()

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.2.1-server/common/ASC.Api.Core/Model/EmployeeDto.cs/#L34 | DocSpace Reference}
 */
export const EmployeeDtoFieldSchema = z.union([
	z.literal("id").describe("The user ID."),
	z.literal("displayName").describe("The user display name."),
	// z.literal("title").describe("The user title."),
	// z.literal("avatar").describe("The user avatar."),
	// z.literal("avatarOriginal").describe("The user original size avatar."),
	// z.literal("avatarMax").describe("The user maximum size avatar."),
	// z.literal("avatarMedium").describe("The user medium size avatar."),
	// z.literal("avatarSmall").describe("The user small size avatar."),
	// z.literal("profileUrl").describe("The user profile URL."),
	// z.literal("hasAvatar").describe("Specifies if the user has an avatar or not."),
	z.literal("isAnonim").describe("Specifies if the user is anonymous or not."),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/common/ASC.Api.Core/Model/EmployeeFullDto.cs/#L34 | DocSpace Reference}
 */
export const EmployeeFullDtoFieldSchema = z.union([
	...EmployeeDtoFieldSchema.options,
	// z.literal("firstName").describe("The user first name."),
	// z.literal("lastName").describe("The user last name."),
	// z.literal("userName").describe("The user username."),
	z.literal("email").describe("The user email."),
	// ...wrapUnion(ContentFieldSchema, "contacts").options,
	z.literal("birthday").describe("The user birthday."),
	// z.literal("sex").describe("The user sex."),
	z.literal("status").describe("The user status."),
	// z.literal("activationStatus").describe("The user activation status."),
	// z.literal("terminated"),
	z.literal("department").describe("The user department."),
	// z.literal("workFrom"),
	// ...wrapUnion(GroupSummaryDtoFieldSchema, "groups").options,
	// z.literal("location").describe("The user location."),
	// z.literal("notes").describe("The user notes."),
	z.literal("isAdmin").describe("Specifies if the user is an administrator or not."),
	z.literal("isRoomAdmin").describe("Specifies if the user is a room administrator or not."),
	// eslint-disable-next-line stylistic/max-len
	// z.literal("isLDAP").describe("Specifies if the LDAP settings are enabled for the user or not."),
	// z.literal("listAdminModules").describe("The list of the administrator modules."),
	z.literal("isOwner").describe("Specifies if the user is a portal owner or not."),
	z.literal("isVisitor").describe("Specifies if the user is a portal visitor or not."),
	z.literal("isCollaborator").describe("Specifies if the user is a portal collaborator or not."),
	// z.literal("cultureName").describe("The user culture code."),
	// z.literal("mobilePhone").describe("The user mobile phone number."),
	// z.literal("mobilePhoneActivationStatus").describe("The mobile phone activation status."),
	// z.literal("isSSO").describe("Specifies if the SSO settings are enabled for the user or not."),
	// z.literal("theme").describe("The user theme settings."),
	// z.literal("quotaLimit").describe("The user quota limit."),
	// z.literal("usedSpace").describe("The portal used space of the user."),
	// z.literal("shared").describe("Specifies if the user has access rights."),
	// z.literal("isCustomQuota").describe("Specifies if the user has a custom quota or not."),
	// z.literal("loginEventId").describe("The current login event ID."),
	// ...wrapUnion(EmployeeDtoFieldSchema, "createdBy").options,
	// z.literal("registrationDate"),
	// z.literal("hasPersonalFolder").describe("Specifies if the user has a personal folder or not."),
	// eslint-disable-next-line stylistic/max-len
	// z.literal("tfaAppEnabled").describe("Indicates whether the user has enabled two-factor authentication (TFA) using an authentication app."),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/ApiModels/RequestDto/ArchiveRoomRequestDto.cs/#L32 | DocSpace Reference}
 */
export const ArchiveRoomRequestSchema = z.object({
	deleteAfter: z.boolean().optional(),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/ApiModels/RequestDto/BatchModelRequestDto.cs/#L43 | DocSpace Reference}
 */
export const BaseBatchRequestDtoSchema = z.object({
	folderIds: z.array(JsonElementSchema).optional(),
	fileIds: z.array(JsonElementSchema).optional(),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/ApiModels/RequestDto/BatchModelRequestDto.cs/#L67 | DocSpace Reference}
 */
export const DownloadRequestItemDtoSchema = z.object({
	key: JsonElementSchema.optional(),
	value: z.string().optional(),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/ApiModels/RequestDto/BatchModelRequestDto.cs/#L59 | DocSpace Reference}
 */
export const DownloadRequestDtoSchema = BaseBatchRequestDtoSchema.extend({
	fileConvertIds: z.array(DownloadRequestItemDtoSchema).optional(),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/ApiModels/RequestDto/BatchModelRequestDto.cs/#L93 | DocSpace Reference}
 */
export const DeleteSchema = z.object({
	deleteAfter: z.boolean().optional(),
	immediately: z.boolean().optional(),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/Services/WCFService/FileOperations/FileConflictResolveType.cs/#L31 | DocSpace Reference}
 */
export const FileConflictResolveTypeSchema = z.union([
	z.literal(0).describe("Skip"),
	z.literal(1).describe("Overwrite"),
	z.literal(2).describe("Duplicate"),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/ApiModels/RequestDto/BatchModelRequestDto.cs/#L127 | DocSpace Reference}
 */
export const BatchRequestDtoSchema = BaseBatchRequestDtoSchema.extend({
	destFolderId: JsonElementSchema.optional(),
	conflictResolveType: FileConflictResolveTypeSchema.optional(),
	deleteAfter: z.boolean().optional(),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/ApiModels/RequestDto/CreateFolderRequestDto.cs/#L32 | DocSpace Reference}
 */
export const CreateFolderSchema = z.object({
	title: z.string().optional(),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/ApiModels/RequestDto/CreateRoomRequestDto.cs/#L30 | DocSpace Reference}
 */
export const RoomTypeSchema = z.union([
	z.literal(1).describe("Form Filling Room. Upload PDF forms into the room. Invite members and guests to fill out a PDF form. Review completed forms and analyze data automatically collected in a spreadsheet."),
	z.literal(2).describe("Collaboration room. Collaborate on one or multiple documents with your team."),
	z.literal(5).describe("Custom room. Apply your own settings to use this room for any custom purpose."),
	z.literal(6).describe("Public room. Share documents for viewing, editing, commenting, or reviewing without registration. You can also embed this room into any web interface."),
	z.literal(8).describe("Virtual Data Room. Use VDR for advanced file security and transparency. Set watermarks, automatically index and track all content, restrict downloading and copying."),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/ApiModels/RequestDto/UpdateRoomRequestDto.cs/#L32 | DocSpace Reference}
 */
export const UpdateRoomRequestSchema = z.object({
	title: z.string().optional(),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/ApiModels/RequestDto/CreateRoomRequestDto.cs/#L72 | DocSpace Reference}
 */
export const CreateRoomRequestDtoSchema = UpdateRoomRequestSchema.extend({
	roomType: numberUnionToEnum(RoomTypeSchema, "").optional(),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/ApiModels/RequestDto/DeleteFolderDto.cs/#L32 | DocSpace Reference}
 */
export const DeleteFolderSchema = z.object({
	deleteAfter: z.boolean().optional(),
	immediately: z.boolean().optional(),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.2.1-server/products/ASC.Files/Core/Core/Entries/FileEntryTypeEnum.cs/#L33 | DocSpace Reference}
 */
export const FileEntityTypeSchema = z.union([
	z.literal(1).describe("Folder"),
	z.literal(2).describe("File"),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.2.1-server/products/ASC.Files/Core/Core/Entries/Folder.cs/#L32 | DocSpace Reference}
 */
export const FolderType = z.union([
	z.literal(0).describe("Default"),
	z.literal(1).describe("Coomon"),
	z.literal(2).describe("Bunch"),
	z.literal(3).describe("Trash"),
	z.literal(5).describe("User"),
	z.literal(6).describe("Share"),
	z.literal(8).describe("Projects"),
	z.literal(10).describe("Favourites"),
	z.literal(11).describe("Recent"),
	z.literal(12).describe("Templates"),
	z.literal(13).describe("Privacy"),
	z.literal(14).describe("Virtual rooms"),
	z.literal(15).describe("Filling forms room"),
	z.literal(16).describe("Editing room"),
	z.literal(19).describe("Custom room"),
	z.literal(20).describe("Archive"),
	z.literal(21).describe("Thirdparty backup"),
	z.literal(22).describe("Public room"),
	z.literal(25).describe("Ready form folder"),
	z.literal(26).describe("In process form folder"),
	z.literal(27).describe("Form filling folder done"),
	z.literal(28).describe("Form filling folder in progress"),
	z.literal(29).describe("Virtual Data Room"),
	z.literal(30).describe("Room templates folder"),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/Core/Security/FileShare.cs/#L31 | DocSpace Reference}
 */
export const FileShareSchema = z.union([
	z.literal(0).describe("None"),
	z.literal(1).describe("Read and write"),
	z.literal(2).describe("Read"),
	z.literal(3).describe("Restrict"),
	z.literal(4).describe("Varies"),
	z.literal(5).describe("Review"),
	z.literal(6).describe("Comment"),
	z.literal(7).describe("Fill forms"),
	z.literal(8).describe("Custom filter"),
	z.literal(9).describe("Room manager"),
	z.literal(10).describe("Editing"),
	z.literal(11).describe("Content creator"),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/ApiModels/RequestDto/RoomInvitation.cs/#L29 | DocSpace Reference}
 */
export const RoomInvitationSchema = EmailInvitationDtoSchema.extend({
	id: z.string().optional(),
	access: numberUnionToEnum(FileShareSchema, "").optional(),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/ApiModels/RequestDto/RoomInvitationRequestDto.cs/#L32 | DocSpace Reference}
 */
export const RoomInvitationRequestSchema = z.object({
	invitations: z.array(RoomInvitationSchema).optional(),
	notify: z.boolean().optional(),
	message: z.string().optional(),
	culture: z.string().optional(),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/ApiModels/RequestDto/SessionRequestDto.cs/#L32 | DocSpace Reference}
 */
export const SessionRequestSchema = z.object({
	fileName: z.string().optional(),
	fileSize: z.number().optional(),
	createOn: z.string().optional(),
	createNewIfExist: z.boolean().optional(),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/ApiModels/RequestDto/UpdateFileRequestDto.cs/#L32 | DocSpace Reference}
 */
export const UpdateFileSchema = z.object({
	title: z.string().optional(),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/web/ASC.Web.Core/Files/FileType.cs/#L32 | DocSpace Reference}
 */
export const FileTypeSchema = z.union([
	z.literal(0).describe("Unknown"),
	z.literal(1).describe("Archive"),
	z.literal(2).describe("Video"),
	z.literal(3).describe("Audio"),
	z.literal(4).describe("Image"),
	z.literal(5).describe("Spreadsheet"),
	z.literal(6).describe("Presentation"),
	z.literal(7).describe("Document"),
	z.literal(10).describe("Pdf"),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.2.1-server/products/ASC.Files/Core/ApiModels/ResponseDto/FileEntryDto.cs/#L45 | DocSpace Reference}
 */
export const FileEntryDtoSchema = z.
	object({
		id: JsonElementSchema.optional().describe("The file entry ID."),
		rootFolderId: JsonElementSchema.optional().describe("The root folder ID of the file entry."),
		canShare: z.boolean().optional().describe("Specifies if the file entry can be shared or not."),
		security: z.unknown().optional().describe("The actions that can be performed with the file entry."),
		title: z.string().optional().describe("The file entry title."),
		access: z.unknown().optional().describe("The access rights to the file entry."),
		shared: z.boolean().optional().describe("Specifies if the file entry is shared or not."),
		created: z.string().optional().describe("The date and time when the file entry was created."),
		createdBy: EmployeeDtoSchema.optional().describe("The user who created the file entry."),
		fileEntityType: numberUnionToEnum(FileEntityTypeSchema, "The file entry type.").optional(),
	}).
	passthrough()

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.2.1-server/products/ASC.Files/Core/ApiModels/ResponseDto/FileEntryDto.cs/#L45 | DocSpace Reference}
 */
export const FileEntryDtoFieldSchema = z.union([
	z.literal("id").describe("The file entry ID."),
	z.literal("rootFolderId").describe("The root folder ID of the file entry."),
	// z.literal("originId").describe("The origin ID of the file entry."),
	// z.literal("originRoomId").describe("The origin room ID of the file entry."),
	// z.literal("originTitle").describe("The origin title of the file entry."),
	// z.literal("originRoomTitle").describe("The origin room title of the file entry."),
	z.literal("canShare").describe("Specifies if the file entry can be shared or not."),
	z.literal("security").describe("The actions that can be performed with the file entry."),
	// z.literal("requestToken").describe("The request token of the file entry."),
	z.literal("title").describe("The file entry title."),
	z.literal("access").describe("The access rights to the file entry."),
	z.literal("shared").describe("Specifies if the file entry is shared or not."),
	z.literal("created").describe("The creation date and time of the file entry."),
	...wrapUnion(EmployeeDtoFieldSchema, "createdBy").options,
	// z.literal("updated"),
	// z.literal("autoDelete"),
	// z.literal("rootFolderType").describe("The root folder type of the file entry."),
	// z.literal("parentRoomType").describe("The parent room type of the file entry."),
	// ...wrapUnion(EmployeeDtoFieldSchema, "updatedBy").options,
	// eslint-disable-next-line stylistic/max-len
	// z.literal("providerItem").describe("Specifies if the file entry provider is specified or not."),
	// z.literal("providerKey").describe("The provider key of the file entry."),
	// z.literal("providerId").describe("The provider ID of the file entry."),
	// z.literal("order").describe("The order of the file entry."),
	z.literal("fileEntryType").describe("The file entry type."),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.2.1-server/products/ASC.Files/Core/ApiModels/ResponseDto/FileDto.cs/#L32 | DocSpace Reference}
 */
export const FileDtoSchema = FileEntryDtoSchema.
	extend({
		folderId: JsonElementSchema.optional().describe("The folder ID where the file is located."),
		fileType: numberUnionToEnum(FileTypeSchema, "The file type.").optional(),
		fileExst: z.string().optional().describe("The file extension."),
		comment: z.string().optional().describe("The comment to the file."),
		encrypted: z.boolean().optional().describe("Specifies if the file is encrypted or not."),
		locked: z.boolean().optional().describe("Specifies if the file is locked or not."),
	}).
	passthrough()

// /**
//  * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Core/ApiModels/ResponseDto/FileDto.cs/#L471 | DocSpace Reference}
//  */
// export const DraftLocationFieldSchema = z.union([
// 	z.literal("folderId").describe("The InProcess folder ID of the draft."),
// 	z.literal("folderTitle").describe("The InProcess folder title of the draft."),
// 	z.literal("fileId").describe("The draft ID."),
// 	z.literal("fileTitle").describe("The draft title."),
// ])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.2.1-server/products/ASC.Files/Core/ApiModels/ResponseDto/FileDto.cs/#L32 | DocSpace Reference}
 */
export const FileDtoFieldSchema = z.union([
	...FileEntryDtoFieldSchema.options,
	z.literal("folderId").describe("The folder ID where the file is located."),
	// z.literal("version").describe("The file version."),
	// z.literal("versionGroup").describe("The version group of the file."),
	// z.literal("contentLength").describe("The content length of the file."),
	// z.literal("pureContentLength").describe("The pure content length of the file."),
	// z.literal("fileStatus").describe("The current status of the file."),
	// z.literal("mute").describe("Specifies if the file is muted or not."),
	// z.literal("viewUrl").describe("The URL link to view the file."),
	// z.literal("webUrl").describe("The Web URL link to the file."),
	// z.literal("shortWebUrl").describe("The short Web URL."),
	z.literal("fileType").describe("The file type."),
	z.literal("fileExst").describe("The file extension."),
	z.literal("comment").describe("The comment to the file."),
	z.literal("encrypted").describe("Specifies if the file is encrypted or not."),
	// z.literal("thumbnailUrl").describe("The thumbnail URL of the file."),
	// z.literal("thumbnailStatus").describe("The current thumbnail status of the file."),
	z.literal("locked").describe("Specifies if the file is locked or not."),
	// z.literal("lockedBy").describe("The user ID of the person who locked the file."),
	// z.literal("hasDraft").describe("Specifies if the file has a draft or not."),
	// z.literal("formFillingStatus").describe("The status of the form filling process."),
	// z.literal("isForm").describe("Specifies if the file is a form or not."),
	// eslint-disable-next-line stylistic/max-len
	// z.literal("customFilterEnabled").describe("Specifies if the Custom Filter editing mode is enabled for a file or not."),
	// eslint-disable-next-line stylistic/max-len
	// z.literal("customFilterEnabledBy").describe("The name of the user who enabled a Custom Filter editing mode for a file."),
	// z.literal("startFilling").describe("Specifies if the filling has started or not."),
	// z.literal("inProcessFolderId").describe("The InProcess folder ID of the file."),
	// z.literal("inProcessFolderTitle").describe("The InProcess folder title of the file."),
	// ...wrapUnion(DraftLocationFieldSchema, "draftLocation").options,
	// z.literal("viewAccessibility").describe("The file accessibility."),
	// z.literal("availableExternalRights").describe("The available external rights of the file."),
	// z.literal("lastOpened"),
	// z.literal("expired"),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/ApiModels/ResponseDto/FileOperationDto.cs/#L29 | DocSpace Reference}
 */
export const FileOperationDtoSchema = z.
	object({
		id: z.string().optional(),
		progress: z.number().optional(),
		error: z.string().optional(),
		finished: z.boolean().optional(),
		url: z.string().optional(),
	}).
	passthrough()

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.2.1-server/products/ASC.Files/Core/Core/Security/SubjectType.cs/#L61 | DocSpace Reference}
 */
export const SubjectTypeSchema = z.union([
	z.literal(0).describe("User"),
	z.literal(1).describe("External link"),
	z.literal(2).describe("Group"),
	z.literal(3).describe("Invitation link"),
	z.literal(4).describe("Primary external link"),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.2.1-server/products/ASC.Files/Core/ApiModels/ResponseDto/FileShareDto.cs/#L32 | DocSpace Reference}
 */
export const FileShareDtoSchema = z.
	object({
		access: numberUnionToEnum(FileShareSchema, "The access rights type.").optional(),
		sharedTo: z.unknown().optional().describe("The user who has the access to the specified file."),
		isLocked: z.boolean().optional().describe("Specifies if the access right is locked or not."),
		isOwner: z.boolean().optional().describe("Specifies if the user is an owner of the specified file or not."),
		canEditAccess: z.boolean().optional().describe("Specifies if the user can edit the access to the specified file or not."),
		subjectType: numberUnionToEnum(SubjectTypeSchema, "The subject type.").optional(),
	}).
	passthrough()

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.2.1-server/products/ASC.Files/Core/ApiModels/ResponseDto/FileShareDto.cs/#L32 | DocSpace Reference}
 */
export const FileShareDtoFieldSchema = z.union([
	z.literal("access").describe("The access rights type."),
	z.literal("sharedTo").describe("The user who has the access to the specified file."),
	z.literal("isLocked").describe("Specifies if the access right is locked or not."),
	z.literal("isOwner").describe("Specifies if the user is an owner of the specified file or not."),
	z.literal("canEditAccess").describe("Specifies if the user can edit the access to the specified file or not."),
	z.literal("subjectType").describe("The subject type."),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Core/ApiModels/ResponseDto/FilesSettingsDto.cs/#L32 | DocSpace Reference}
 */
export const FilesSettingsDtoSchema = z.
	object({
		extsConvertible: z.record(z.string(), z.array(z.string()).optional()).optional(),
	}).
	passthrough()

// /**
//  * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Core/Core/VirtualRooms/Logo.cs/#L73 | DocSpace Reference}
//  */
// export const LogoCoverFieldSchema = z.union([
// 	z.literal("id").describe("The logo cover ID."),
// 	z.literal("data").describe("The logo cover data."),
// ])

// /**
//  * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Core/Core/VirtualRooms/Logo.cs/#L32 | DocSpace Reference}
//  */
// export const LogoFieldSchema = z.union([
// 	z.literal("original").describe("The original logo."),
// 	z.literal("large").describe("The large logo."),
// 	z.literal("medium").describe("The medium logo."),
// 	z.literal("small").describe("The small logo."),
// 	z.literal("color").describe("The logo color."),
// 	...wrapUnion(LogoCoverFieldSchema, "cover").options,
// ])

// /**
//  * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Core/ApiModels/RoomDataLifetimeDto.cs/#L32 | DocSpace Reference}
//  */
// export const RoomDataLifetimeDtoFieldSchema = z.union([
// eslint-disable-next-line stylistic/max-len
// 	z.literal("deletePermanently").describe("Specifies whether to permanently delete the room data or not."),
// 	z.literal("period").describe("Specifies the time period type of the room data lifetime."),
// 	z.literal("value").describe("Specifies the time period value of the room data lifetime."),
// eslint-disable-next-line stylistic/max-len
// 	z.literal("enabled").describe("Specifies whether the room data lifetime setting is enabled or not."),
// ])

// /**
//  * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Core/ApiModels/ResponseDto/WatermarkDto.cs/#L32 | DocSpace Reference}
//  */
// export const WatermarkDtoFieldSchema = z.union([
// eslint-disable-next-line stylistic/max-len
// 	z.literal("additions").describe("Specifies whether to display in the watermark: username, user email, user ip-adress, current date, and room name."),
// 	z.literal("text").describe("The watermark text."),
// 	z.literal("rotate").describe("The watermark text and image rotate."),
// 	z.literal("imageScale").describe("The watermark image scale."),
// 	z.literal("imageUrl").describe("The watermark image url."),
// 	z.literal("imageHeight").describe("The watermark image height."),
// 	z.literal("imageWidth").describe("The watermark image width."),
// ])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.2.1-server/products/ASC.Files/Core/ApiModels/ResponseDto/FolderDto.cs/#L32 | DocSpace Reference}
 */
export const FolderDtoSchema = FileEntryDtoSchema.
	extend({
		parentId: JsonElementSchema.optional().describe("The parent folder ID of the folder."),
		filesCount: z.number().optional().describe("The number of files that the folder contains."),
		foldersCount: z.number().optional().describe("The number of folders that the folder contains."),
		isShareable: z.boolean().optional().describe("Specifies if the folder can be shared or not."),
		isFavorite: z.boolean().optional().describe("Specifies if the folder is favorite or not."),
		tags: z.array(z.string()).optional().describe("The list of tags of the folder."),
		roomType: numberUnionToEnum(RoomTypeSchema, "The room type of the folder.").optional(),
		private: z.boolean().optional().describe("Specifies if the folder is private or not."),
		type: numberUnionToEnum(FolderType, "The folder type.").optional(),
		inRoom: z.boolean().optional().describe("Specifies if the folder is placed in the room or not."),
	}).
	passthrough()

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.2.1-server/products/ASC.Files/Core/ApiModels/ResponseDto/FolderDto.cs/#L32 | DocSpace Reference}
 */
export const FolderDtoFieldSchema = z.union([
	...FileEntryDtoFieldSchema.options,
	z.literal("parentId").describe("The parent folder ID of the folder."),
	z.literal("filesCount").describe("The number of files that the folder contains."),
	z.literal("foldersCount").describe("The number of folders that the folder contains."),
	z.literal("isShareable").describe("Specifies if the folder can be shared or not."),
	z.literal("isFavorite").describe("Specifies if the folder is favorite or not."),
	// z.literal("new").describe("The new element index in the folder."),
	// z.literal("mute").describe("Specifies if the folder notifications are enabled or not."),
	z.literal("tags").describe("The list of tags of the folder."),
	// ...wrapUnion(LogoFieldSchema, "logo").options,
	// z.literal("pinned").describe("Specifies if the folder is pinned or not."),
	z.literal("roomType").describe("The room type of the folder."),
	z.literal("private").describe("Specifies if the folder is private or not."),
	// z.literal("indexing").describe("Specifies if the folder is indexed or not."),
	// z.literal("denyDownload").describe("Specifies if the folder can be downloaded or not."),
	// ...wrapUnion(RoomDataLifetimeDtoFieldSchema, "lifetime").options,
	// ...wrapUnion(WatermarkDtoFieldSchema, "watermark").options,
	z.literal("type").describe("The folder type."),
	z.literal("inRoom").describe("Specifies if the folder is placed in the room or not."),
	// z.literal("quotaLimit").describe("The folder quota limit."),
	// z.literal("isCustomQuota").describe("Specifies if the folder room has a custom quota or not."),
	// z.literal("usedSpace").describe("How much folder space is used (counter)."),
	// eslint-disable-next-line stylistic/max-len
	// z.literal("external").describe("Specifies if the folder can be accessed via an external link or not."),
	// eslint-disable-next-line stylistic/max-len
	// z.literal("passwordProtected").describe("Specifies if the folder is password protected or not."),
	// eslint-disable-next-line stylistic/max-len
	// z.literal("expired").describe("Specifies if an external link to the folder is expired or not."),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.2.1-server/products/ASC.Files/Core/ApiModels/ResponseDto/FolderContentDto.cs/#L32 | DocSpace Reference}
 */
export const FolderContentDtoSchema = z.
	object({
		files: z.array(FileEntryDtoSchema).optional().describe("The list of files in the folder."),
		folders: z.array(FileEntryDtoSchema).optional().describe("The list of folders in the folder."),
		current: FolderDtoSchema.optional().describe("The current folder information."),
		startIndex: z.number().optional().describe("The folder start index."),
		count: z.number().optional().describe("The number of folder elements."),
		total: z.number().optional().describe("The total number of elements in the folder."),
	}).
	passthrough()

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.2.1-server/products/ASC.Files/Core/ApiModels/ResponseDto/FolderContentDto.cs/#L32 | DocSpace Reference}
 */
export const FolderContentDtoFieldSchema = z.union([
	...wrapUnion(FileDtoFieldSchema, "files").options,
	...wrapUnion(FolderDtoFieldSchema, "folders").options,
	...wrapUnion(FolderDtoFieldSchema, "current").options,
	// z.literal("pathParts").describe("The folder path."),
	z.literal("startIndex").describe("The folder start index."),
	z.literal("count").describe("The number of folder elements."),
	z.literal("total").describe("The total number of elements in the folder."),
	// z.literal("new").describe("The new element index in the folder."),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.2.1-server/products/ASC.Files/Core/ApiModels/ResponseDto/RoomAccessDto.cs/#L32 | DocSpace Reference}
 */
export const RoomSecurityDtoSchema = z.
	object({
		members: z.array(FileShareDtoSchema).optional().describe("The list of room members."),
		warning: z.string().optional().describe("The warning message."),
		error: z.unknown().optional().describe("The error type."),
	}).
	passthrough()

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.2.1-server/products/ASC.Files/Core/ApiModels/ResponseDto/RoomAccessDto.cs/#L32 | DocSpace Reference}
 */
export const RoomSecurityDtoFieldSchema = z.union([
	...wrapUnion(FileShareDtoFieldSchema, "members").options,
	z.literal("warning").describe("The warning message."),
	z.literal("error").describe("The error type."),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Core/Core/ApplyFilterOption.cs/#L29 | DocSpace Reference}
 */
export const ApplyFilterOptionSchema = z.union([
	z.literal("All"),
	z.literal("Files"),
	z.literal("Folders"),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Core/Core/FilterTypeEnum.cs/#L32 | DocSpace Reference}
 */
export const FilterTypeSchema = z.union([
	z.literal(0).describe("None"),
	z.literal(1).describe("Files only"),
	z.literal(2).describe("Folders only"),
	z.literal(3).describe("Documents only"),
	z.literal(4).describe("Presentations only"),
	z.literal(5).describe("Spreadsheets only"),
	z.literal(7).describe("Images only"),
	z.literal(8).describe("By user"),
	z.literal(9).describe("By department"),
	z.literal(10).describe("Archive only"),
	z.literal(11).describe("By extension"),
	z.literal(12).describe("Media only"),
	z.literal(13).describe("Filling forms rooms"),
	z.literal(14).describe("Editing rooms"),
	z.literal(17).describe("Custom rooms"),
	z.literal(20).describe("Public rooms"),
	z.literal(22).describe("Pdf"),
	z.literal(23).describe("Pdf form"),
	z.literal(24).describe("Virtual data rooms"),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Core/Core/Security/SubjectType.cs/#L33 | DocSpace Reference}
 */
export const ShareFilterTypeSchema = z.union([
	z.literal(0).describe("User or group"),
	z.literal(1).describe("Invitation link"),
	z.literal(2).describe("External link"),
	z.literal(4).describe("Additional external link"),
	z.literal(8).describe("Primary external link"),
	z.literal(16).describe("User"),
	z.literal(32).describe("Group"),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Core/Core/VirtualRooms/SearchArea.cs/#L32 | DocSpace Reference}
 */
export const SearchAreaSchema = z.union([
	z.literal("Active"),
	z.literal("Archive"),
	z.literal("Any"),
	z.literal("RecentByLinks"),
	z.literal("Template"),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/HttpHandlers/ChunkedUploaderHandler.cs/#L218 | DocSpace Reference}
 */
export const UploadChunkErrorResponseSchema = z.object({
	success: z.literal(false),
	message: z.string(),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/HttpHandlers/ChunkedUploaderHandler.cs/#L233 | DocSpace Reference}
 */
export const UploadChunkSuccessResponseSchema = z.object({
	success: z.literal(true),
	data: TypeObjectSchema,
	message: z.string(),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Helpers/UploadControllerHelper.cs/#L97 | DocSpace Reference}
 */
export const UploadSessionObjectDataSchema = z.
	object({
		id: z.string().optional(),
	}).
	passthrough()

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Helpers/UploadControllerHelper.cs/#L97 | DocSpace Reference}
 */
export const UploadSessionObjectSchema = z.object({
	success: z.boolean(),
	data: TypeObjectSchema,
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/web/ASC.Web.Api/ApiModels/RequestsDto/AuthRequestsDto.cs/#L32 | DocSpace Reference}
 */
export const AuthRequestsDtoSchema = z.object({
	userName: z.string().optional(),
	password: z.string().optional(),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/web/ASC.Web.Api/ApiModels/ResponseDto/AuthenticationTokenDto.cs/#L29 | DocSpace Reference}
 */
export const AuthenticationTokenDtoSchema = z.
	object({
		token: z.string().optional(),
		expires: z.string().optional(),
	}).
	passthrough()

export const GetFileInfoFiltersSchema = z.object({
	fields: z.array(stringUnionToEnum(FileDtoFieldSchema, "The fields to include in the response.")),
})

export const CreateFolderFiltersSchema = z.object({
	fields: z.array(stringUnionToEnum(FolderDtoFieldSchema, "The fields to include in the response.")),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Core/ApiModels/RequestDto/GetFolderRequestDto.cs/#L32 | DocSpace Reference}
 */
export const GetFolderFiltersSchema = z.object({
	userIdOrGroupId: z.string().uuid().optional().describe("The user or group ID."),
	filterType: numberUnionToEnum(FilterTypeSchema, "The filter type.").optional(),
	roomId: JsonElementSchema.optional().describe("The room ID."),
	excludeSubject: z.boolean().optional().describe("Specifies whether to exclude search by user or group ID."),
	applyFilterOption: ApplyFilterOptionSchema.optional().describe("Specifies whether to return only files, only folders or all elements from the specified folder."),
	extension: z.string().optional().describe("Specifies whether to search for the specific file extension."),
	searchArea: SearchAreaSchema.optional().describe("The search area."),
	// formsItemKey: z.string().describe("The forms item key."),
	// formsItemType: z.string().describe("The forms item type."),
	count: z.number().min(1).max(50).default(30).describe("The maximum number of items to retrieve in the request."),
	startIndex: z.number().optional().describe("The zero-based index of the first item to retrieve in a paginated request."),
	sortBy: z.string().optional().describe("Specifies the property used for sorting the folder request results."),
	sortOrder: numberUnionToEnum(NumericSortOrderSchema, "The order in which the results are sorted.").optional(),
	filterValue: z.string().optional().describe("The text value used as a filter parameter for folder queries."),
	fields: z.array(stringUnionToEnum(FolderContentDtoFieldSchema, "The fields to include in the response.")),
})

export const GetFolderInfoFiltersSchema = z.object({
	fields: z.array(stringUnionToEnum(FolderDtoFieldSchema, "The fields to include in the response.")),
})

export const RenameFolderFiltersSchema = z.object({
	fields: z.array(stringUnionToEnum(FolderDtoFieldSchema, "The fields to include in the response.")),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Core/ApiModels/RequestDto/GetFolderRequestDto.cs/#L116 | DocSpace Reference}
 */
export const GetMyFolderFiltersSchema = z.object({
	userIdOrGroupId: z.string().uuid().optional().describe("The user or group ID."),
	filterType: numberUnionToEnum(FilterTypeSchema, "The filter type.").optional(),
	applyFilterOption: ApplyFilterOptionSchema.optional().describe("Specifies whether to return only files, only folders or all elements."),
	count: z.number().min(1).max(50).default(30).describe("The maximum number of items to retrieve in the response."),
	startIndex: z.number().optional().describe("The starting position of the items to be retrieved."),
	sortBy: z.string().optional().describe("The property used to specify the sorting criteria for folder contents."),
	sortOrder: numberUnionToEnum(NumericSortOrderSchema, "The order in which the results are sorted.").optional(),
	filterValue: z.string().optional().describe("The text used for filtering or searching folder contents."),
	fields: z.array(stringUnionToEnum(FolderContentDtoFieldSchema, "The fields to include in the response.")),
})

export const CreateRoomFiltersSchema = z.object({
	fields: z.array(stringUnionToEnum(FolderDtoFieldSchema, "The fields to include in the response.")),
})

export const GetRoomInfoFiltersSchema = z.object({
	fields: z.array(stringUnionToEnum(FolderDtoFieldSchema, "The fields to include in the response.")),
})

export const UpdateRoomFiltersSchema = z.object({
	fields: z.array(stringUnionToEnum(FolderDtoFieldSchema, "The fields to include in the response.")),
})

export const SetRoomSecurityFiltersSchema = z.object({
	fields: z.array(stringUnionToEnum(RoomSecurityDtoFieldSchema, "The fields to include in the response.")),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Core/ApiModels/RequestDto/RoomSecurityInfoRequestDto.cs/#L32 | DocSpace Reference}
 */
export const GetRoomSecurityFiltersSchema = z.object({
	filterType: numberUnionToEnum(ShareFilterTypeSchema, "The filter type of the access rights.").optional(),
	count: z.number().min(1).max(50).default(30).describe("The number of items to be retrieved or processed."),
	startIndex: z.number().optional().describe("The starting index of the items to retrieve in a paginated request."),
	filterValue: z.string().optional().describe("The text filter value used for filtering room security information."),
	fields: z.array(stringUnionToEnum(FileShareDtoFieldSchema, "The fields to include in the response.")),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Core/ApiModels/RequestDto/RoomContentRequestDto.cs/#L32 | DocSpace Reference}
 */
export const GetRoomsFolderFiltersSchema = z.object({
	type: z.array(numberUnionToEnum(RoomTypeSchema, "The filter by room type.")).optional(),
	subjectId: z.string().optional().describe("The filter by user ID."),
	searchArea: SearchAreaSchema.optional().describe("The room search area (Active, Archive, Any, Recent by links)."),
	withoutTags: z.boolean().optional().describe("Specifies whether to search by tags or not."),
	tags: z.string().optional().describe("The tags in the serialized format."),
	excludeSubject: z.boolean().optional().describe("Specifies whether to exclude search by user or group ID."),
	// eslint-disable-next-line stylistic/max-len
	// provider: ProviderFilterSchema.optional().describe("The filter by provider name (None, Box, DropBox, GoogleDrive, kDrive, OneDrive, SharePoint, WebDav, Yandex, Storage)."),
	// eslint-disable-next-line stylistic/max-len
	// subjectFilter: SubjectFilterSchema.optional().describe("The filter by user (Owner - 0, Member - 1)."),
	// eslint-disable-next-line stylistic/max-len
	// quotaFilter: QuotaFilterSchema.optional().describe("The filter by quota (All - 0, Default - 1, Custom - 2)."),
	// eslint-disable-next-line stylistic/max-len
	// storageFilter: StorageFilterSchema.optional().describe("The filter by storage (None - 0, Internal - 1, ThirdParty - 2)."),
	count: z.number().min(1).max(50).default(30).describe("Specifies the maximum number of items to retrieve."),
	startIndex: z.number().optional().describe("The index from which to start retrieving the room content."),
	sortBy: z.string().optional().describe("Specifies the field by which the room content should be sorted."),
	sortOrder: numberUnionToEnum(NumericSortOrderSchema, "The order in which the results are sorted.").optional(),
	filterValue: z.string().optional().describe("The text used for filtering or searching folder contents."),
	fields: z.array(stringUnionToEnum(FolderContentDtoFieldSchema, "The fields to include in the response.")),
})

export const GetAllFiltersSchema = z.object({
	count: z.number().min(1).max(50).default(30).describe("The maximum number of items to be retrieved in the response."),
	startIndex: z.number().optional().describe("The zero-based index of the first item to be retrieved in a filtered result set."),
	filterBy: z.string().optional().describe("Specifies the filter criteria for user-related queries."),
	sortBy: z.string().optional().describe("Specifies the property or field name by which the results should be sorted."),
	sortOrder: numberUnionToEnum(NumericSortOrderSchema, "The order in which the results are sorted.").optional(),
	filterSeparator: z.string().optional().describe("The character or string used to separate multiple filter values in a filtering query."),
	filterValue: z.string().optional().describe("The text value used as an additional filter criterion for profiles retrieval."),
	fields: z.array(stringUnionToEnum(EmployeeFullDtoFieldSchema, "The fields to include in the response.")),
})
