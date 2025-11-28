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

import path from "node:path"
import * as z from "zod"
import type {JsonSchema7Type} from "zod-to-json-schema"
import {zodToJsonSchema} from "zod-to-json-schema"
import {
	CreateFolderFiltersSchema,
	CreateRoomFiltersSchema,
	EmployeeDtoSchema,
	FileDtoSchema,
	FileShareDtoSchema,
	FolderContentDtoSchema,
	FolderDtoSchema,
	GetFileInfoFiltersSchema,
	GetFolderFiltersSchema,
	GetFolderInfoFiltersSchema,
	GetFullByFilterFiltersSchema,
	GetMyFolderFiltersSchema,
	GetRoomInfoFiltersSchema,
	GetRoomSecurityFiltersSchema,
	GetRoomsFolderFiltersSchema,
	RenameFolderFiltersSchema,
	RoomSecurityDtoSchema,
	RoomTypeSchema,
	SetRoomSecurityFiltersSchema,
	SuccessApiResponseSchema,
	UpdateRoomFiltersSchema,
} from "../api/schemas.ts"
import type {
	BulkDownloadOptions,
	CopyBatchItemsOptions,
	CreateFolderOptions,
	CreateRoomOptions,
	CreateUploadSessionOptions,
	DeleteFileOptions,
	DeleteFolderOptions,
	MoveBatchItemsOptions,
	RenameFolderOptions,
	Response,
	SetRoomSecurityOptions,
	UpdateFileOptions,
	UpdateRoomOptions,
} from "../api.ts"
import type {Result} from "../util/result.ts"
import {error, ok, safeAsync, safeSync} from "../util/result.ts"
import {numberUnionToEnum} from "../util/zod.ts"
import type {ConfiguredServer} from "./configured-server.ts"

//
// Files
//

export const DeleteFileInputSchema = z.object({
	fileId: z.number().describe("The ID of the file to delete."),
})

export const GetFileInfoInputSchema = z.object({
	fileId: z.number().describe("The ID of the file to get info for."),
	filters: GetFileInfoFiltersSchema.describe("The filters to apply to the file info. Use them to reduce the size of the response."),
})

export const GetFileInfoOutputSchema = SuccessApiResponseSchema.extend({
	response: FileDtoSchema.describe("The file information."),
})

export const UpdateFileInputSchema = z.object({
	fileId: z.number().describe("The ID of the file to update."),
	title: z.string().describe("The new title of the file to set."),
})

export const UpdateFileOutputSchema = SuccessApiResponseSchema.extend({
	response: FileDtoSchema.describe("The updated file information."),
})

export const CopyBatchItemsInputSchema = z.object({
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

export const MoveBatchItemsInputSchema = z.object({
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

export const DownloadFileAsTextInputSchema = z.object({
	fileId: z.number().describe("The ID of the file to download as text."),
})

export const UploadFileInputSchema = z.object({
	parentId: z.number().describe("The ID of the room or folder to upload the file to."),
	filename: z.string().describe("The file name with an extension to upload."),
	content: z.string().describe("The content of the file to upload."),
})

//
// Folders
//

export const CreateFolderInputSchema = z.object({
	parentId: z.number().describe("The ID of the room or folder to create the folder in."),
	title: z.string().describe("The title of the folder to create."),
	filters: CreateFolderFiltersSchema.describe("The filters to apply to the folder creation. Use them to reduce the size of the response."),
})

export const CreateFolderOutputSchema = SuccessApiResponseSchema.extend({
	response: FolderDtoSchema.describe("The created folder information."),
})

export const DeleteFolderInputSchema = z.object({
	folderId: z.number().describe("The ID of the folder to delete."),
})

export const GetFolderContentInputSchema = z.object({
	folderId: z.number().describe("The ID of the folder to get."),
	filters: GetFolderFiltersSchema.describe("The filters to apply to the contents of the folder. Use them to reduce the size of the response."),
})

export const GetFolderContentOutputSchema = SuccessApiResponseSchema.extend({
	response: FolderContentDtoSchema.describe("The contents of the folder."),
})

export const GetFolderInfoInputSchema = z.object({
	folderId: z.number().describe("The ID of the folder to get info for."),
	filters: GetFolderInfoFiltersSchema.describe("The filters to apply to the folder info. Use them to reduce the size of the response."),
})

export const GetFolderInfoOutputSchema = SuccessApiResponseSchema.extend({
	response: FolderDtoSchema.describe("The folder information."),
})

export const RenameFolderInputSchema = z.object({
	folderId: z.number().describe("The ID of the folder to rename."),
	title: z.string().describe("The new title of the folder to set."),
	filters: RenameFolderFiltersSchema.describe("The filters to apply to the folder renaming. Use them to reduce the size of the response."),
})

export const RenameFolderOutputSchema = SuccessApiResponseSchema.extend({
	response: FolderDtoSchema.describe("The renamed folder information."),
})

export const GetMyFolderInputSchema = z.object({
	filters: GetMyFolderFiltersSchema.describe("The filters to apply to the My Documents folder. Use them to reduce the size of the response."),
})

export const GetMyFolderOutputSchema = SuccessApiResponseSchema.extend({
	response: FolderContentDtoSchema.describe("The contents of the My Documents folder."),
})

//
// Rooms
//

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
	/* eslint-disable no-underscore-dangle */
	RoomInvitationAccessSchema._def.options[4],
	RoomInvitationAccessSchema._def.options[5],
	RoomInvitationAccessSchema._def.options[7],
	/* eslint-enable no-underscore-dangle */
])

const CollaborationRoomInvitationAccessSchema = z.union([
	/* eslint-disable no-underscore-dangle */
	RoomInvitationAccessSchema._def.options[1],
	RoomInvitationAccessSchema._def.options[5],
	RoomInvitationAccessSchema._def.options[6],
	RoomInvitationAccessSchema._def.options[7],
	/* eslint-enable no-underscore-dangle */
])

const CustomRoomInvitationAccessSchema = z.union([
	/* eslint-disable no-underscore-dangle */
	RoomInvitationAccessSchema._def.options[1],
	RoomInvitationAccessSchema._def.options[2],
	RoomInvitationAccessSchema._def.options[3],
	RoomInvitationAccessSchema._def.options[5],
	RoomInvitationAccessSchema._def.options[6],
	RoomInvitationAccessSchema._def.options[7],
	/* eslint-enable no-underscore-dangle */
])

const PublicRoomInvitationAccessSchema = z.union([
	/* eslint-disable no-underscore-dangle */
	RoomInvitationAccessSchema._def.options[5],
	RoomInvitationAccessSchema._def.options[7],
	/* eslint-enable no-underscore-dangle */
])

const VirtualDataRoomInvitationAccessSchema = z.union([
	/* eslint-disable no-underscore-dangle */
	RoomInvitationAccessSchema._def.options[1],
	RoomInvitationAccessSchema._def.options[4],
	RoomInvitationAccessSchema._def.options[5],
	RoomInvitationAccessSchema._def.options[6],
	RoomInvitationAccessSchema._def.options[7],
	/* eslint-enable no-underscore-dangle */
])

export const CreateRoomInputSchema = z.object({
	title: z.string().describe("The title of the room to create."),
	roomType: numberUnionToEnum(RoomTypeSchema, "The type of the room to create.").optional().default(6),
	filters: CreateRoomFiltersSchema.describe("The filters to apply to the room creation."),
})

export const CreateRoomOutputSchema = SuccessApiResponseSchema.extend({
	response: FolderContentDtoSchema.describe("The contents of the created room."),
})

export const GetRoomInfoInputSchema = z.object({
	roomId: z.number().describe("The ID of the room to get info for."),
	filters: GetRoomInfoFiltersSchema.describe("The filters to apply to the room info."),
})

export const GetRoomInfoOutputSchema = SuccessApiResponseSchema.extend({
	response: FolderDtoSchema.describe("The room information."),
})

export const UpdateRoomInputSchema = z.object({
	roomId: z.number().describe("The ID of the room to update."),
	title: z.string().optional().describe("The new title of the room to set."),
	filters: UpdateRoomFiltersSchema.describe("The filters to apply to the room update."),
})

export const UpdateRoomOutputSchema = SuccessApiResponseSchema.extend({
	response: FolderDtoSchema.describe("The updated room information."),
})

export const ArchiveRoomInputSchema = z.object({
	roomId: z.number().describe("The ID of the room to archive."),
})

export const SetRoomSecurityInputSchema = z.object({
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
					access: numberUnionToEnum(RoomInvitationAccessSchema, "The access level to grant to the user. May vary depending on the type of room.").
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
	filters: SetRoomSecurityFiltersSchema.describe("The filters to apply to the room security info."),
})

export const SetRoomSecurityOutputSchema = SuccessApiResponseSchema.extend({
	response: RoomSecurityDtoSchema.describe("The room security information after the operation."),
})

export const GetRoomSecurityInfoInputSchema = z.object({
	roomId: z.number().describe("The ID of the room to get a list of users with their access level for."),
	filters: GetRoomSecurityFiltersSchema.describe("The filters to apply to the room security info."),
})

export const GetRoomSecurityInfoOutputSchema = SuccessApiResponseSchema.extend({
	response: z.array(FileShareDtoSchema).describe("The room security information."),
})

export const GetRoomsFolderInputSchema = z.object({
	filters: GetRoomsFolderFiltersSchema.describe("The filters to apply to the rooms folder."),
})

export const GetRoomsFolderOutputSchema = SuccessApiResponseSchema.extend({
	response: FolderContentDtoSchema.describe("The contents of the rooms folder."),
})

export const GetRoomAccessLevelsSchema = z.object({
	roomId: z.number().describe("The ID of the room to get the invitation access for."),
})

//
// People
//

export const GetAllPeopleInputSchema = z.object({
	filters: GetFullByFilterFiltersSchema.describe("The filters to apply to the list of people. Use them to reduce the size of the response."),
})

export const GetAllPeopleOutputSchema = SuccessApiResponseSchema.extend({
	response: z.array(EmployeeDtoSchema),
})

export class RegularTools {
	private s: ConfiguredServer

	constructor(s: ConfiguredServer) {
		this.s = s
	}

	//
	// Files
	//

	async deleteFile(signal: AbortSignal, p: unknown): Promise<Result<string, Error>> {
		let pr = DeleteFileInputSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let tr = await this.s.client.files.getTrashFolder(signal)
		if (tr.err) {
			return error(new Error("Getting trash folder.", {cause: tr.err}))
		}

		let [td] = tr.v

		if (!td.current) {
			return error(new Error("Trash folder is not defined."))
		}

		if (!td.current.id) {
			return error(new Error("Trash folder ID is not defined."))
		}

		let fr = await this.s.client.files.getFileInfo(signal, pr.data.fileId)
		if (fr.err) {
			return error(new Error("Getting file info.", {cause: fr.err}))
		}

		let [gd] = fr.v

		if (!gd.folderId) {
			return error(new Error("File folder ID is not defined."))
		}

		if (gd.folderId === td.current.id) {
			return ok("File is already in the trash folder.")
		}

		let dp: DeleteFileOptions = {
			deleteAfter: false,
			immediately: false,
		}

		let dr = await this.s.client.files.deleteFile(signal, pr.data.fileId, dp)
		if (dr.err) {
			return error(new Error("Deleting file.", {cause: dr.err}))
		}

		let [dd] = dr.v

		let rr = await this.s.resolver.resolve(signal, ...dd)
		if (rr.err) {
			return error(new Error("Resolving delete file operations.", {cause: rr.err}))
		}

		return ok("File deleted.")
	}

	async getFileInfo(signal: AbortSignal, p: unknown): Promise<Result<Response, Error>> {
		let pr = GetFileInfoInputSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let gr = await this.s.client.files.getFileInfo(signal, pr.data.fileId, pr.data.filters)
		if (gr.err) {
			return error(new Error("Getting file info.", {cause: gr.err}))
		}

		let [, res] = gr.v

		return ok(res)
	}

	async updateFile(signal: AbortSignal, p: unknown): Promise<Result<Response, Error>> {
		let pr = UpdateFileInputSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let uo: UpdateFileOptions = {
			title: pr.data.title,
		}

		let ur = await this.s.client.files.updateFile(signal, pr.data.fileId, uo)
		if (ur.err) {
			return error(new Error("Updating file.", {cause: ur.err}))
		}

		let [, res] = ur.v

		return ok(res)
	}

	async copyBatchItems(signal: AbortSignal, p: unknown): Promise<Result<string, Error>> {
		let pr = CopyBatchItemsInputSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let co: CopyBatchItemsOptions = {
			// @ts-ignore See the type above for the reason.
			folderIds: pr.data.folderIds,
			// @ts-ignore See the type above for the reason.
			fileIds: pr.data.fileIds,
			// @ts-ignore See the type above for the reason.
			destFolderId: pr.data.destFolderId,
			conflictResolveType: 2,
			deleteAfter: false,
		}

		let cr = await this.s.client.files.copyBatchItems(signal, co)
		if (cr.err) {
			return error(new Error("Copying batch items.", {cause: cr.err}))
		}

		let [cd] = cr.v

		let rr = await this.s.resolver.resolve(signal, ...cd)
		if (rr.err) {
			return error(new Error("Resolving copy batch items operations.", {cause: rr.err}))
		}

		return ok("Batch items copied.")
	}

	async moveBatchItems(signal: AbortSignal, p: unknown): Promise<Result<string, Error>> {
		let pr = MoveBatchItemsInputSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let mo: MoveBatchItemsOptions = {
			// @ts-ignore See the type above for the reason.
			folderIds: pr.data.folderIds,
			// @ts-ignore See the type above for the reason.
			fileIds: pr.data.fileIds,
			// @ts-ignore See the type above for the reason.
			destFolderId: pr.data.destFolderId,
			conflictResolveType: 2,
			deleteAfter: false,
		}

		let mr = await this.s.client.files.moveBatchItems(signal, mo)
		if (mr.err) {
			return error(new Error("Moving batch items.", {cause: mr.err}))
		}

		let [md] = mr.v

		let rr = await this.s.resolver.resolve(signal, ...md)
		if (rr.err) {
			return error(new Error("Resolving move batch items operations.", {cause: rr.err}))
		}

		return ok("Batch items moved.")
	}

	async downloadFileAsText(signal: AbortSignal, p: unknown): Promise<Result<string, Error>> {
		let pr = DownloadFileAsTextInputSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let ir = await this.s.client.files.getFileInfo(signal, pr.data.fileId)
		if (ir.err) {
			return error(new Error("Getting file info.", {cause: ir.err}))
		}

		let [id] = ir.v

		if (!id.fileExst) {
			return error(new Error("File extension is not defined."))
		}

		let ex: string | undefined

		if (id.fileExst === ".csv" || id.fileExst === ".txt") {
			ex = id.fileExst
		} else {
			let sr = await this.s.client.files.getFilesSettings(signal)
			if (sr.err) {
				return error(new Error("Getting files settings.", {cause: sr.err}))
			}

			let [sd] = sr.v

			if (!sd.extsConvertible) {
				return error(new Error("Convertible file extensions are not defined."))
			}

			let fr = sd.extsConvertible[id.fileExst]

			if (!fr) {
				return error(new Error(`File extension ${id.fileExst} is not convertible.`))
			}

			for (let e of fr) {
				if (e === ".csv" || e === ".txt") {
					ex = e
					break
				}
			}
		}

		if (!ex) {
			return error(new Error(`No convertible extension found for ${id.fileExst}.`))
		}

		let bo: BulkDownloadOptions = {
			fileConvertIds: [{key: pr.data.fileId, value: ex}],
		}

		let br = await this.s.client.files.bulkDownload(signal, bo)
		if (br.err) {
			return error(new Error("Making bulk download.", {cause: br.err}))
		}

		let [bd] = br.v

		let rr = await this.s.resolver.resolve(signal, ...bd)
		if (rr.err) {
			return error(new Error("Resolving bulk download operations.", {cause: rr.err}))
		}

		if (rr.v.operations.length === 0) {
			return error(new Error("No resolved operations."))
		}

		if (rr.v.operations.length > 1) {
			return error(new Error(`Expected 1 resolved operation, got ${rr.v.operations.length}.`))
		}

		let [rd] = rr.v.operations

		if (rd.url === undefined) {
			return error(new Error("Resolved operation has no URL."))
		}

		let dr = this.s.client.createRequest(signal, "GET", rd.url)
		if (dr.err) {
			return error(new Error("Creating download request.", {cause: dr.err}))
		}

		let hr = safeSync(dr.v.headers.set.bind(dr.v.headers), "Accept", "text/plain")
		if (hr.err) {
			return error(new Error("Setting header.", {cause: hr.err}))
		}

		let tr = await this.s.client.bareFetch(dr.v)
		if (tr.err) {
			return error(new Error("Downloading file.", {cause: tr.err}))
		}

		let tt = await safeAsync(tr.v.text.bind(tr.v))
		if (tt.err) {
			return error(new Error("Converting response to text.", {cause: tt.err}))
		}

		return ok(tt.v)
	}

	async uploadFile(signal: AbortSignal, p: unknown): Promise<Result<Response, Error>> {
		let pr = UploadFileInputSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let fp = path.parse(pr.data.filename)

		if (!fp.ext) {
			return error(new Error("File extension is missing in the filename."))
		}

		let te = new TextEncoder()

		let buf = te.encode(pr.data.content)

		let so: CreateUploadSessionOptions = {
			fileName: pr.data.filename,
			fileSize: buf.length,
			createOn: new Date().toISOString(),
			createNewIfExist: true,
		}

		let sr = await this.s.client.files.createUploadSession(signal, pr.data.parentId, so)
		if (sr.err) {
			return error(new Error("Creating upload session.", {cause: sr.err}))
		}

		let [sd] = sr.v

		if (sd.id === undefined) {
			return error(new Error("Upload session ID is not defined."))
		}

		let ur = await this.s.uploader.upload(signal, sd.id, buf)
		if (ur.err) {
			return error(new Error("Uploading file.", {cause: ur.err}))
		}

		let [, res] = ur.v

		return ok(res)
	}

	//
	// Folders
	//

	async createFolder(signal: AbortSignal, p: unknown): Promise<Result<Response, Error>> {
		let pr = CreateFolderInputSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let co: CreateFolderOptions = {
			title: pr.data.title,
		}

		let cr = await this.s.client.files.createFolder(signal, pr.data.parentId, co, pr.data.filters)
		if (cr.err) {
			return error(new Error("Creating folder.", {cause: cr.err}))
		}

		let [, res] = cr.v

		return ok(res)
	}

	async deleteFolder(signal: AbortSignal, p: unknown): Promise<Result<string, Error>> {
		let pr = DeleteFolderInputSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let dp: DeleteFolderOptions = {
			deleteAfter: false,
			immediately: false,
		}

		let dr = await this.s.client.files.deleteFolder(signal, pr.data.folderId, dp)
		if (dr.err) {
			return error(new Error("Deleting folder.", {cause: dr.err}))
		}

		let [dd] = dr.v

		let rr = await this.s.resolver.resolve(signal, ...dd)
		if (rr.err) {
			return error(new Error("Resolving delete folder operations.", {cause: rr.err}))
		}

		return ok("Folder deleted.")
	}

	async getFolderContent(signal: AbortSignal, p: unknown): Promise<Result<Response, Error>> {
		let pr = GetFolderContentInputSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let gr = await this.s.client.files.getFolder(signal, pr.data.folderId, pr.data.filters)
		if (gr.err) {
			return error(new Error("Getting folder.", {cause: gr.err}))
		}

		let [, res] = gr.v

		return ok(res)
	}

	async getFolderInfo(signal: AbortSignal, p: unknown): Promise<Result<Response, Error>> {
		let pr = GetFolderInfoInputSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let gr = await this.s.client.files.getFolderInfo(signal, pr.data.folderId, pr.data.filters)
		if (gr.err) {
			return error(new Error("Getting folder info.", {cause: gr.err}))
		}

		let [, res] = gr.v

		return ok(res)
	}

	async renameFolder(signal: AbortSignal, p: unknown): Promise<Result<Response, Error>> {
		let pr = RenameFolderInputSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let ro: RenameFolderOptions = {
			title: pr.data.title,
		}

		let rr = await this.s.client.files.renameFolder(signal, pr.data.folderId, ro, pr.data.filters)
		if (rr.err) {
			return error(new Error("Renaming folder.", {cause: rr.err}))
		}

		let [, res] = rr.v

		return ok(res)
	}

	async getMyFolder(signal: AbortSignal, p: unknown): Promise<Result<Response, Error>> {
		let pr = GetMyFolderInputSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let gr = await this.s.client.files.getMyFolder(signal, pr.data.filters)
		if (gr.err) {
			return error(new Error("Getting my folder.", {cause: gr.err}))
		}

		let [, res] = gr.v

		return ok(res)
	}

	//
	// Rooms
	//

	async createRoom(signal: AbortSignal, p: unknown): Promise<Result<Response, Error>> {
		let pr = CreateRoomInputSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let co: CreateRoomOptions = {
			title: pr.data.title,
			roomType: pr.data.roomType,
		}

		let cr = await this.s.client.files.createRoom(signal, co, pr.data.filters)
		if (cr.err) {
			return error(new Error("Creating room.", {cause: cr.err}))
		}

		let [, res] = cr.v

		return ok(res)
	}

	async getRoomInfo(signal: AbortSignal, p: unknown): Promise<Result<Response, Error>> {
		let pr = GetRoomInfoInputSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let gr = await this.s.client.files.getRoomInfo(signal, pr.data.roomId, pr.data.filters)
		if (gr.err) {
			return error(new Error("Getting room info.", {cause: gr.err}))
		}

		let [, res] = gr.v

		return ok(res)
	}

	async updateRoom(signal: AbortSignal, p: unknown): Promise<Result<Response, Error>> {
		let pr = UpdateRoomInputSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let uo: UpdateRoomOptions = {
			title: pr.data.title,
		}

		let ur = await this.s.client.files.updateRoom(signal, pr.data.roomId, uo, pr.data.filters)
		if (ur.err) {
			return error(new Error("Updating room.", {cause: ur.err}))
		}

		let [, res] = ur.v

		return ok(res)
	}

	async archiveRoom(signal: AbortSignal, p: unknown): Promise<Result<string, Error>> {
		let pr = ArchiveRoomInputSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let ar = await this.s.client.files.archiveRoom(signal, pr.data.roomId, {})
		if (ar.err) {
			return error(new Error("Archiving room.", {cause: ar.err}))
		}

		let [ad] = ar.v

		let rr = await this.s.resolver.resolve(signal, ad)
		if (rr.err) {
			return error(new Error("Resolving archive room operations.", {cause: rr.err}))
		}

		return ok("Room archived.")
	}

	async setRoomSecurity(signal: AbortSignal, p: unknown): Promise<Result<Response, Error>> {
		let pr = SetRoomSecurityInputSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let so: SetRoomSecurityOptions = {
			invitations: pr.data.invitations,
			notify: pr.data.notify,
			message: pr.data.message,
		}

		let sr = await this.s.client.files.setRoomSecurity(signal, pr.data.roomId, so, pr.data.filters)
		if (sr.err) {
			return error(new Error("Setting room security.", {cause: sr.err}))
		}

		let [, res] = sr.v

		return ok(res)
	}

	async getRoomSecurityInfo(signal: AbortSignal, p: unknown): Promise<Result<Response, Error>> {
		let pr = GetRoomSecurityInfoInputSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let gr = await this.s.client.files.getRoomSecurityInfo(signal, pr.data.roomId, pr.data.filters)
		if (gr.err) {
			return error(new Error("Getting room security info.", {cause: gr.err}))
		}

		let [, res] = gr.v

		return ok(res)
	}

	async getRoomsFolder(signal: AbortSignal, p: unknown): Promise<Result<Response, Error>> {
		let pr = GetRoomsFolderInputSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let gr = await this.s.client.files.getRoomsFolder(signal, pr.data.filters)
		if (gr.err) {
			return error(new Error("Getting rooms folder.", {cause: gr.err}))
		}

		let [, res] = gr.v

		return ok(res)
	}

	getRoomTypes(): Result<JsonSchema7Type, Error> {
		return ok(zodToJsonSchema(RoomTypeSchema))
	}

	async getRoomAccessLevels(signal: AbortSignal, p: unknown): Promise<Result<JsonSchema7Type, Error>> {
		let pr = GetRoomAccessLevelsSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let gr = await this.s.client.files.getRoomInfo(signal, pr.data.roomId)
		if (gr.err) {
			return error(new Error("Getting room info.", {cause: gr.err}))
		}

		let [gd] = gr.v

		if (!gd.roomType) {
			return error(new Error("Room type is not defined."))
		}

		let sh: z.ZodSchema<unknown>

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

		return ok(zodToJsonSchema(sh))
	}

	//
	// People
	//

	async getAllPeople(signal: AbortSignal, p: unknown): Promise<Result<Response, Error>> {
		let pr = GetAllPeopleInputSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let gr = await this.s.client.people.getFullByFilter(signal, pr.data.filters)
		if (gr.err) {
			return error(new Error("Getting people.", {cause: gr.err}))
		}

		let [, res] = gr.v

		return ok(res)
	}
}
