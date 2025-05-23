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

export type Filters = z.infer<typeof FiltersSchema>

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
	count: z.number().optional(),
	startIndex: z.number().optional(),
	sortBy: z.union([SortedByTypeSchema, z.string()]).optional(),
	sortOrder: SortOderSchema.optional(),
	filterBy: z.string().optional(),
	filterOp: FilterOpSchema.optional(),
	filterValue: z.string().optional(),
	updatedSince: z.string().optional(),
})

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
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/common/ASC.Api.Core/Model/EmailInvitationDto.cs/#L36 | DocSpace Reference}
 */
export const EmailInvitationDtoSchema = z.object({
	email: z.string().optional(),
})

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
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Core/ApiModels/ResponseDto/FileDto.cs/#L29 | DocSpace Reference}
 */
export const FileDtoSchema = z.
	object({
		fileType: FileTypeSchema.optional(),
	}).
	passthrough()

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
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.0-server/products/ASC.Files/Core/ApiModels/ResponseDto/FolderDto.cs/#L32 | DocSpace Reference}
 */
export const FolderDtoSchema = z.
	object({
		roomType: RoomTypeSchema.optional(),
	}).
	passthrough()

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
