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

import * as z from "zod"
import {wrapUnion} from "../../../util/zod.ts"

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

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/Core/Entries/OrderBy.cs/#L30 | DocSpace Reference}
 */
export const SortedByTypeSchema = z.union([
	z.literal("DateAndTime"),
	z.literal("AZ"),
	z.literal("Size"),
	z.literal("Author"),
	z.literal("Type"),
	z.literal("New"),
	z.literal("DateAndTimeCreation"),
	z.literal("RoomType"),
	z.literal("Tags"),
	z.literal("Room"),
	z.literal("CustomOrder"),
	z.literal("LastOpened"),
	z.literal("UsedSpace"),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/common/ASC.Api.Core/Core/ApiContext.cs/#L94 | DocSpace Reference}
 */
export const SortOderSchema = z.union([
	z.literal("ascending"),
	z.literal("descending"),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/common/ASC.Api.Core/Core/ApiContext.cs/#L83 | DocSpace Reference}
 */
export const FilterOpSchema = z.union([
	z.literal("contains"),
	z.literal("equals"),
	z.literal("startsWith"),
	z.literal("present"),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/common/ASC.Api.Core/Core/ApiContext.cs/#L32 | DocSpace Reference}
 */
export const FiltersSchema = z.object({
	count: z.number().optional().describe("The number of items to return."),
	startIndex: z.number().optional().describe("The number of items to skip before starting to return items."),
	sortBy: z.union([SortedByTypeSchema, z.string()]).optional().describe("The field to sort by."),
	sortOrder: SortOderSchema.optional().describe("The order to sort by."),
	filterBy: z.string().optional().describe("The field to filter by."),
	filterOp: FilterOpSchema.optional().describe("The operation to use for filtering."),
	filterValue: z.string().optional().describe("The value to filter by."),
	updatedSince: z.string().optional().describe("The date to filter items updated or created since."),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/common/ASC.Api.Core/Core/ApiDateTime.cs/#L36 | DocSpace Reference}
 */
export const ApiDateTimeFieldSchema = z.union([
	z.literal("utcTime").describe("The time in UTC format."),
	z.literal("timeZoneOffset").describe("The time zone offset."),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/common/ASC.Api.Core/Middleware/CommonApiResponse.cs/#L31 | DocSpace Reference}
 */
export const CommonApiResponseSchema = z.object({
	status: z.number(),
	statusCode: z.number(),
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
	response: TypeObjectSchema,
	count: z.number().optional(),
	total: z.number().optional(),
	links: z.array(LinkSchema),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/common/ASC.Api.Core/Model/Contact.cs/#L32 | DocSpace Reference}
 */
export const ContentFieldSchema = z.union([
	z.literal("type").describe("The contact type."),
	z.literal("value").describe("The contact value."),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/common/ASC.Api.Core/Model/GroupSummaryDto.cs/#L34 | DocSpace Reference}
 */
export const GroupSummaryDtoFieldSchema = z.union([
	z.literal("id").describe("The group ID."),
	z.literal("name").describe("The group name."),
	z.literal("manager").describe("The group manager."),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/common/ASC.Api.Core/Model/EmailInvitationDto.cs/#L36 | DocSpace Reference}
 */
export const EmailInvitationDtoSchema = z.object({
	email: z.string().optional(),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/common/ASC.Api.Core/Model/EmployeeDto.cs/#L34 | DocSpace Reference}
 */
export const EmployeeDtoFieldSchema = z.union([
	z.literal("id").describe("The user ID."),
	z.literal("displayName").describe("The user display name."),
	z.literal("title").describe("The user title."),
	z.literal("avatar").describe("The user avatar."),
	z.literal("avatarOriginal").describe("The user original size avatar."),
	z.literal("avatarMax").describe("The user maximum size avatar."),
	z.literal("avatarMedium").describe("The user medium size avatar."),
	z.literal("avatarSmall").describe("The user small size avatar."),
	z.literal("profileUrl").describe("The user profile URL."),
	z.literal("hasAvatar").describe("Specifies if the user has an avatar or not."),
	z.literal("isAnonim").describe("Specifies if the user is anonymous or not."),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/common/ASC.Api.Core/Model/EmployeeFullDto.cs/#L34 | DocSpace Reference}
 */
export const EmployeeFullDtoFieldSchema = z.union([
	...EmployeeDtoFieldSchema.options,
	z.literal("firstName").describe("The user first name."),
	z.literal("lastName").describe("The user last name."),
	z.literal("userName").describe("The user username."),
	z.literal("email").describe("The user email."),
	...wrapUnion(ContentFieldSchema, "contacts").options,
	...wrapUnion(ApiDateTimeFieldSchema, "birthday").options,
	z.literal("sex").describe("The user sex."),
	z.literal("status").describe("The user status."),
	z.literal("activationStatus").describe("The user activation status."),
	...wrapUnion(ApiDateTimeFieldSchema, "terminated").options,
	z.literal("department").describe("The user department."),
	...wrapUnion(ApiDateTimeFieldSchema, "workFrom").options,
	...wrapUnion(GroupSummaryDtoFieldSchema, "groups").options,
	z.literal("location").describe("The user location."),
	z.literal("notes").describe("The user notes."),
	z.literal("isAdmin").describe("Specifies if the user is an administrator or not."),
	z.literal("isRoomAdmin").describe("Specifies if the user is a room administrator or not."),
	z.literal("isLDAP").describe("Specifies if the LDAP settings are enabled for the user or not."),
	z.literal("listAdminModules").describe("The list of the administrator modules."),
	z.literal("isOwner").describe("Specifies if the user is a portal owner or not."),
	z.literal("isVisitor").describe("Specifies if the user is a portal visitor or not."),
	z.literal("isCollaborator").describe("Specifies if the user is a portal collaborator or not."),
	z.literal("cultureName").describe("The user culture code."),
	z.literal("mobilePhone").describe("The user mobile phone number."),
	z.literal("mobilePhoneActivationStatus").describe("The mobile phone activation status."),
	z.literal("isSSO").describe("Specifies if the SSO settings are enabled for the user or not."),
	z.literal("theme").describe("The user theme settings."),
	z.literal("quotaLimit").describe("The user quota limit."),
	z.literal("usedSpace").describe("The portal used space of the user."),
	z.literal("shared").describe("Specifies if the user has access rights."),
	z.literal("isCustomQuota").describe("Specifies if the user has a custom quota or not."),
	z.literal("loginEventId").describe("The current login event ID."),
	...wrapUnion(EmployeeDtoFieldSchema, "createdBy").options,
	...wrapUnion(ApiDateTimeFieldSchema, "registrationDate").options,
	z.literal("hasPersonalFolder").describe("Specifies if the user has a personal folder or not."),
	z.literal("tfaAppEnabled").describe("Indicates whether the user has enabled two-factor authentication (TFA) using an authentication app."),
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
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/ApiModels/RequestDto/BatchModelRequestDto.cs/#L127 | DocSpace Reference}
 */
export const BatchRequestDtoSchema = BaseBatchRequestDtoSchema.extend({
	destFolderId: JsonElementSchema.optional(),
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
export const RoomTypeSchema = z.
	union([
		z.literal(1),
		z.literal(2),
		z.literal(5),
		z.literal(6),
		z.literal(8),
		z.literal("FillingFormsRoom"),
		z.literal("EditingRoom"),
		z.literal("CustomRoom"),
		z.literal("PublicRoom"),
		z.literal("VirtualDataRoom"),
	]).
	transform((v) => {
		// DocSpace has a bug that does not allow the use string literals.
		switch (v) {
		case "FillingFormsRoom":
			return 1
		case "EditingRoom":
			return 2
		case "CustomRoom":
			return 5
		case "PublicRoom":
			return 6
		case "VirtualDataRoom":
			return 8
		default:
			return v
		}
	})

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
	roomType: RoomTypeSchema.optional(),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/ApiModels/RequestDto/DeleteFolderDto.cs/#L32 | DocSpace Reference}
 */
export const DeleteFolderSchema = z.object({
	deleteAfter: z.boolean().optional(),
	immediately: z.boolean().optional(),
})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/Core/Security/FileShare.cs/#L31 | DocSpace Reference}
 */
export const FileShareSchema = z.
	union([
		z.literal(0),
		z.literal(1),
		z.literal(2),
		z.literal(3),
		z.literal(4),
		z.literal(5),
		z.literal(6),
		z.literal(7),
		z.literal(8),
		z.literal(9),
		z.literal(10),
		z.literal(11),
		z.literal("None"),
		z.literal("ReadWrite"),
		z.literal("Read"),
		z.literal("Restrict"),
		z.literal("Varies"),
		z.literal("Review"),
		z.literal("Comment"),
		z.literal("FillForms"),
		z.literal("CustomFilter"),
		z.literal("RoomManager"),
		z.literal("Editing"),
		z.literal("ContentCreator"),
	]).
	transform((v) => {
		// DocSpace has a bug that does not allow the use string literals.
		switch (v) {
		case "None":
			return 0
		case "ReadWrite":
			return 1
		case "Read":
			return 2
		case "Restrict":
			return 3
		case "Varies":
			return 4
		case "Review":
			return 5
		case "Comment":
			return 6
		case "FillForms":
			return 7
		case "CustomFilter":
			return 8
		case "RoomManager":
			return 9
		case "Editing":
			return 10
		case "ContentCreator":
			return 11
		default:
			return v
		}
	})

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/ApiModels/RequestDto/RoomInvitation.cs/#L29 | DocSpace Reference}
 */
export const RoomInvitationSchema = EmailInvitationDtoSchema.extend({
	id: z.string().optional(),
	access: FileShareSchema.optional(),
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
	z.literal(0),
	z.literal(1),
	z.literal(2),
	z.literal(3),
	z.literal(4),
	z.literal(5),
	z.literal(6),
	z.literal(7),
	z.literal(10),
	z.literal("Unknown"),
	z.literal("Archive"),
	z.literal("Video"),
	z.literal("Audio"),
	z.literal("Image"),
	z.literal("Spreadsheet"),
	z.literal("Presentation"),
	z.literal("Document"),
	z.literal("Pdf"),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Core/ApiModels/ResponseDto/FileEntryDto.cs/#L45 | DocSpace Reference}
 */
export const FileEntryDtoFieldSchema = z.union([
	z.literal("id").describe("The file entry ID."),
	z.literal("rootFolderId").describe("The root folder ID of the file entry."),
	z.literal("originId").describe("The origin ID of the file entry."),
	z.literal("originRoomId").describe("The origin room ID of the file entry."),
	z.literal("originTitle").describe("The origin title of the file entry."),
	z.literal("originRoomTitle").describe("The origin room title of the file entry."),
	z.literal("canShare").describe("Specifies if the file entry can be shared or not."),
	z.literal("security").describe("The actions that can be perforrmed with the file entry."),
	z.literal("requestToken").describe("The request token of the file entry."),
	z.literal("title").describe("The file entry title."),
	z.literal("access").describe("The access rights to the file entry."),
	z.literal("shared").describe("Specifies if the file entry is shared or not."),
	...wrapUnion(ApiDateTimeFieldSchema, "created").options,
	...wrapUnion(EmployeeDtoFieldSchema, "createdBy").options,
	...wrapUnion(ApiDateTimeFieldSchema, "updated").options,
	...wrapUnion(ApiDateTimeFieldSchema, "autoDelete").options,
	z.literal("rootFolderType").describe("The root folder type of the file entry."),
	z.literal("parentRoomType").describe("The parent room type of the file entry."),
	...wrapUnion(EmployeeDtoFieldSchema, "updatedBy").options,
	z.literal("providerItem").describe("Specifies if the file entry provider is specified or not."),
	z.literal("providerKey").describe("The provider key of the file entry."),
	z.literal("providerId").describe("The provider ID of the file entry."),
	z.literal("order").describe("The order of the file entry."),
	z.literal("fileEntryType").describe("The file entry type."),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/ApiModels/ResponseDto/FileDto.cs/#L29 | DocSpace Reference}
 */
export const FileDtoSchema = z.
	object({
		fileType: FileTypeSchema.optional(),
	}).
	passthrough()

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Core/ApiModels/ResponseDto/FileDto.cs/#L471 | DocSpace Reference}
 */
export const DraftLocationFieldSchema = z.union([
	z.literal("folderId").describe("The InProcess folder ID of the draft."),
	z.literal("folderTitle").describe("The InProcess folder title of the draft."),
	z.literal("fileId").describe("The draft ID."),
	z.literal("fileTitle").describe("The draft title."),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/ApiModels/ResponseDto/FileDto.cs/#L29 | DocSpace Reference}
 */
export const FileDtoFieldSchema = z.union([
	...FileEntryDtoFieldSchema.options,
	z.literal("folderId").describe("The folder ID where the file is located."),
	z.literal("version").describe("The file version."),
	z.literal("versionGroup").describe("The version group of the file."),
	z.literal("contentLength").describe("The content length of the file."),
	z.literal("pureContentLength").describe("The pure content length of the file."),
	z.literal("fileStatus").describe("The current status of the file."),
	z.literal("mute").describe("Specifies if the file is muted or not."),
	z.literal("viewUrl").describe("The URL link to view the file."),
	z.literal("webUrl").describe("The Web URL link to the file."),
	z.literal("shortWebUrl").describe("The short Web URL."),
	z.literal("fileType").describe("The file type."),
	z.literal("fileExst").describe("The file extension."),
	z.literal("comment").describe("The comment to the file."),
	z.literal("encrypted").describe("Specifies if the file is encrypted or not."),
	z.literal("thumbnailUrl").describe("The thumbnail URL of the file."),
	z.literal("thumbnailStatus").describe("The current thumbnail status of the file."),
	z.literal("locked").describe("Specifies if the file is locked or not."),
	z.literal("lockedBy").describe("The user ID of the person who locked the file."),
	z.literal("hasDraft").describe("Specifies if the file has a draft or not."),
	z.literal("formFillingStatus").describe("The status of the form filling process."),
	z.literal("isForm").describe("Specifies if the file is a form or not."),
	z.literal("customFilterEnabled").describe("Specifies if the Custom Filter editing mode is enabled for a file or not."),
	z.literal("customFilterEnabledBy").describe("The name of the user who enabled a Custom Filter editing mode for a file."),
	z.literal("startFilling").describe("Specifies if the filling has started or not."),
	z.literal("inProcessFolderId").describe("The InProcess folder ID of the file."),
	z.literal("inProcessFolderTitle").describe("The InProcess folder title of the file."),
	...wrapUnion(DraftLocationFieldSchema, "draftLocation").options,
	z.literal("viewAccessibility").describe("The file accessibility."),
	z.literal("availableExternalRights").describe("The available external rights of the file."),
	...wrapUnion(ApiDateTimeFieldSchema, "lastOpened").options,
	...wrapUnion(ApiDateTimeFieldSchema, "expired").options,
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
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Core/ApiModels/ResponseDto/FileShareDto.cs/#L32 | DocSpace Reference}
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
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Core/Core/VirtualRooms/Logo.cs/#L73 | DocSpace Reference}
 */
export const LogoCoverFieldSchema = z.union([
	z.literal("id").describe("The logo cover ID."),
	z.literal("data").describe("The logo cover data."),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Core/Core/VirtualRooms/Logo.cs/#L32 | DocSpace Reference}
 */
export const LogoFieldSchema = z.union([
	z.literal("original").describe("The original logo."),
	z.literal("large").describe("The large logo."),
	z.literal("medium").describe("The medium logo."),
	z.literal("small").describe("The small logo."),
	z.literal("color").describe("The logo color."),
	...wrapUnion(LogoCoverFieldSchema, "cover").options,
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Core/ApiModels/RoomDataLifetimeDto.cs/#L32 | DocSpace Reference}
 */
export const RoomDataLifetimeDtoFieldSchema = z.union([
	z.literal("deletePermanently").describe("Specifies whether to permanently delete the room data or not."),
	z.literal("period").describe("Specifies the time period type of the room data lifetime."),
	z.literal("value").describe("Specifies the time period value of the room data lifetime."),
	z.literal("enabled").describe("Specifies whether the room data lifetime setting is enabled or not."),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Core/ApiModels/ResponseDto/WatermarkDto.cs/#L32 | DocSpace Reference}
 */
export const WatermarkDtoFieldSchema = z.union([
	z.literal("additions").describe("Specifies whether to display in the watermark: username, user email, user ip-adress, current date, and room name."),
	z.literal("text").describe("The watermark text."),
	z.literal("rotate").describe("The watermark text and image rotate."),
	z.literal("imageScale").describe("The watermark image scale."),
	z.literal("imageUrl").describe("The watermark image url."),
	z.literal("imageHeight").describe("The watermark image height."),
	z.literal("imageWidth").describe("The watermark image width."),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.0-server/products/ASC.Files/Core/ApiModels/ResponseDto/FolderDto.cs/#L32 | DocSpace Reference}
 */
export const FolderDtoSchema = z.
	object({
		roomType: RoomTypeSchema.optional(),
	}).
	passthrough()

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Core/ApiModels/ResponseDto/FolderDto.cs/#L32 | DocSpace Reference}
 */
export const FolderDtoFieldSchema = z.union([
	...FileEntryDtoFieldSchema.options,
	z.literal("parentId").describe("The parent folder ID of the folder."),
	z.literal("filesCount").describe("The number of files that the folder contains."),
	z.literal("foldersCount").describe("The number of folders that the folder contains."),
	z.literal("isShareable").describe("Specifies if the folder can be shared or not."),
	z.literal("isFavorite").describe("Specifies if the folder is favorite or not."),
	z.literal("new").describe("The new element index in the folder."),
	z.literal("mute").describe("Specifies if the folder notifications are enabled or not."),
	z.literal("tags").describe("The list of tags of the folder."),
	...wrapUnion(LogoFieldSchema, "logo").options,
	z.literal("pinned").describe("Specifies if the folder is pinned or not."),
	z.literal("roomType").describe("The room type of the folder."),
	z.literal("private").describe("Specifies if the folder is private or not."),
	z.literal("indexing").describe("Specifies if the folder is indexed or not."),
	z.literal("denyDownload").describe("Specifies if the folder can be downloaded or not."),
	...wrapUnion(RoomDataLifetimeDtoFieldSchema, "lifetime").options,
	...wrapUnion(WatermarkDtoFieldSchema, "watermark").options,
	z.literal("type").describe("The folder type."),
	z.literal("inRoom").describe("Specifies if the folder is placed in the room or not."),
	z.literal("quotaLimit").describe("The folder quota limit."),
	z.literal("isCustomQuota").describe("Specifies if the folder room has a custom quota or not."),
	z.literal("usedSpace").describe("How much folder space is used (counter)."),
	z.literal("external").describe("Specifies if the folder can be accessed via an external link or not."),
	z.literal("passwordProtected").describe("Specifies if the folder is password protected or not."),
	z.literal("expired").describe("Specifies if an external link to the folder is expired or not."),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Core/ApiModels/ResponseDto/FolderContentDto.cs/#L32 | DocSpace Reference}
 */
export const FolderContentDtoFieldSchema = z.union([
	...wrapUnion(FileDtoFieldSchema, "files").options,
	...wrapUnion(FolderDtoFieldSchema, "folders").options,
	...wrapUnion(FolderDtoFieldSchema, "current").options,
	z.literal("pathParts").describe("The folder path."),
	z.literal("startIndex").describe("The folder start index."),
	z.literal("count").describe("The number of folder elements."),
	z.literal("total").describe("The total number of elements in the folder."),
	z.literal("new").describe("The new element index in the folder."),
])

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Core/ApiModels/ResponseDto/RoomAccessDto.cs/#L32 | DocSpace Reference}
 */
export const RoomSecurityDtoFieldSchema = z.union([
	...wrapUnion(FileShareDtoFieldSchema, "members").options,
	z.literal("warning").describe("The warning message."),
	z.literal("error").describe("The error type."),
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
	fields: z.array(FileDtoFieldSchema).optional().describe("The fields to include in the response."),
})

export const CreateFolderFiltersSchema = z.object({
	fields: z.array(FolderDtoFieldSchema).optional().describe("The fields to include in the response."),
})

export const GetFolderFiltersSchema = FiltersSchema.extend({
	fields: z.array(FolderContentDtoFieldSchema).optional().describe("The fields to include in the response."),
})

export const GetFolderInfoFiltersSchema = z.object({
	fields: z.array(FolderDtoFieldSchema).optional().describe("The fields to include in the response."),
})

export const GetFoldersFiltersSchema = z.object({
	fields: z.array(FileEntryDtoFieldSchema).optional().describe("The fields to include in the response."),
})

export const RenameFolderFiltersSchema = z.object({
	fields: z.array(FolderDtoFieldSchema).optional().describe("The fields to include in the response."),
})

export const GetMyFolderFiltersSchema = FiltersSchema.extend({
	fields: z.array(FolderContentDtoFieldSchema).optional().describe("The fields to include in the response."),
})

export const CreateRoomFiltersSchema = z.object({
	fields: z.array(FolderDtoFieldSchema).optional().describe("The fields to include in the response."),
})

export const GetRoomInfoFiltersSchema = z.object({
	fields: z.array(FolderDtoFieldSchema).optional().describe("The fields to include in the response."),
})

export const UpdateRoomFiltersSchema = z.object({
	fields: z.array(FolderDtoFieldSchema).optional().describe("The fields to include in the response."),
})

export const SetRoomSecurityFiltersSchema = FiltersSchema.extend({
	fields: z.array(RoomSecurityDtoFieldSchema).optional().describe("The fields to include in the response."),
})

export const GetRoomSecurityFiltersSchema = FiltersSchema.extend({
	fields: z.array(RoomSecurityDtoFieldSchema).optional().describe("The fields to include in the response."),
})

export const GetRoomsFolderFiltersSchema = FiltersSchema.extend({
	fields: z.array(FolderContentDtoFieldSchema).optional().describe("The fields to include in the response."),
})

export const GetAllFiltersSchema = FiltersSchema.extend({
	fields: z.array(EmployeeFullDtoFieldSchema).optional().describe("The fields to include in the response."),
})
