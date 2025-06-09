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
import type {Result} from "../../util/result.ts"
import {error, ok} from "../../util/result.ts"
import {
	CreateFolderFiltersSchema,
	CreateRoomFiltersSchema,
	GetFileInfoFiltersSchema,
	GetFolderFiltersSchema,
	GetFolderInfoFiltersSchema,
	GetFoldersFiltersSchema,
	GetMyFolderFiltersSchema,
	GetRoomInfoFiltersSchema,
	GetRoomSecurityFiltersSchema,
	GetRoomsFolderFiltersSchema,
	RenameFolderFiltersSchema,
	SetRoomSecurityFiltersSchema,
	UpdateRoomFiltersSchema,
} from "../client/internal/schemas.ts"
import type {
	CopyBatchItemsOptions,
	CreateFolderOptions,
	CreateRoomOptions,
	DeleteFileOptions,
	DeleteFolderOptions,
	FilesService, // eslint-disable-line typescript/no-unused-vars
	MoveBatchItemsOptions,
	RenameFolderOptions,
	Response,
	SetRoomSecurityOptions,
	UpdateFileOptions,
	UpdateRoomOptions,
} from "../client.ts"
import type {Server} from "../server.ts"
import {RoomInvitationAccessSchema, RoomTypeSchema} from "./internal/schemas.ts"

export const DeleteFileInputSchema = z.object({
	fileId: z.number().describe("The ID of the file to delete."),
})

export const GetFileInfoInputSchema = z.object({
	fileId: z.number().describe("The ID of the file to get info for."),
	filters: GetFileInfoFiltersSchema.optional().describe("The filters to apply to the file info. Use them to reduce the size of the response."),
})

export const UpdateFileInputSchema = z.object({
	fileId: z.number().describe("The ID of the file to update."),
	title: z.string().describe("The new title of the file to set."),
})

export const CreateFolderInputSchema = z.object({
	parentId: z.number().describe("The ID of the room or folder to create the folder in."),
	title: z.string().describe("The title of the folder to create."),
	filters: CreateFolderFiltersSchema.optional().describe("The filters to apply to the folder creation. Use them to reduce the size of the response."),
})

export const DeleteFolderInputSchema = z.object({
	folderId: z.number().describe("The ID of the folder to delete."),
})

export const GetFolderInputSchema = z.object({
	folderId: z.number().describe("The ID of the folder to get."),
	filters: GetFolderFiltersSchema.optional().default({count: 30}).describe("The filters to apply to the contents of the folder. Use them to reduce the size of the response."),
})

export const GetFolderInfoInputSchema = z.object({
	folderId: z.number().describe("The ID of the folder to get info for."),
	filters: GetFolderInfoFiltersSchema.optional().describe("The filters to apply to the folder info. Use them to reduce the size of the response."),
})

export const GetFoldersInputSchema = z.object({
	folderId: z.number().describe("The ID of the folder to get subfolders for."),
	filters: GetFoldersFiltersSchema.optional().describe("The filters to apply to the subfolders. Use them to reduce the size of the response."),
})

export const RenameFolderInputSchema = z.object({
	folderId: z.number().describe("The ID of the folder to rename."),
	title: z.string().describe("The new title of the folder to set."),
	filters: RenameFolderFiltersSchema.optional().describe("The filters to apply to the folder renaming. Use them to reduce the size of the response."),
})

export const GetMyFolderInputSchema = z.object({
	filters: GetMyFolderFiltersSchema.optional().describe("The filters to apply to the My Documents folder. Use them to reduce the size of the response."),
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

export const CreateRoomInputSchema = z.object({
	title: z.string().describe("The title of the room to create."),
	roomType: RoomTypeSchema.optional().default("PublicRoom").describe("The type of the room to create."),
	filters: CreateRoomFiltersSchema.optional().describe("The filters to apply to the room creation."),
})

export const GetRoomInfoInputSchema = z.object({
	roomId: z.number().describe("The ID of the room to get info for."),
	filters: GetRoomInfoFiltersSchema.optional().describe("The filters to apply to the room info."),
})

export const UpdateRoomInputSchema = z.object({
	roomId: z.number().describe("The ID of the room to update."),
	title: z.string().optional().describe("The new title of the room to set."),
	filters: UpdateRoomFiltersSchema.optional().describe("The filters to apply to the room update."),
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
					access: RoomInvitationAccessSchema.
						optional().
						describe("The access level to grant to the user. May vary depending on the type of room."),
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
	filters: SetRoomSecurityFiltersSchema.optional().default({count: 30}).describe("The filters to apply to the room security info."),
})

export const GetRoomSecurityInfoInputSchema = z.object({
	roomId: z.number().describe("The ID of the room to get a list of users with their access level for."),
	filters: GetRoomSecurityFiltersSchema.optional().default({count: 30}).describe("The filters to apply to the room security info."),
})

export const GetRoomsFolderInputSchema = z.object({
	filters: GetRoomsFolderFiltersSchema.optional().default({count: 30}).describe("The filters to apply to the rooms folder."),
})

export class FilesToolset {
	private s: Server

	constructor(s: Server) {
		this.s = s
	}

	/**
	 * {@link FilesService.deleteFile}
	 */
	async deleteFile(signal: AbortSignal, p: unknown): Promise<Result<string, Error>> {
		let pr = DeleteFileInputSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
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

	/**
	 * {@link FilesService.getFileInfo}
	 */
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

	/**
	 * {@link FilesService.updateFile}
	 */
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

	/**
	 * {@link FilesService.createFolder}
	 */
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

	/**
	 * {@link FilesService.deleteFolder}
	 */
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

	/**
	 * {@link FilesService.getFolder}
	 */
	async getFolder(signal: AbortSignal, p: unknown): Promise<Result<Response, Error>> {
		let pr = GetFolderInputSchema.safeParse(p)
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

	/**
	 * {@link FilesService.getFolderInfo}
	 */
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

	/**
	 * {@link FilesService.getFolders}
	 */
	async getFolders(signal: AbortSignal, p: unknown): Promise<Result<Response, Error>> {
		let pr = GetFoldersInputSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let gr = await this.s.client.files.getFolders(signal, pr.data.folderId)
		if (gr.err) {
			return error(new Error("Getting folders.", {cause: gr.err}))
		}

		let [, res] = gr.v

		return ok(res)
	}

	/**
	 * {@link FilesService.renameFolder}
	 */
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

	/**
	 * {@link FilesService.getMyFolder}
	 */
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

	/**
	 * {@link FilesService.copyBatchItems}
	 */
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

	/**
	 * {@link FilesService.getOperationStatuses}
	 */
	async getOperationStatuses(signal: AbortSignal): Promise<Result<Response, Error>> {
		let gr = await this.s.client.files.getOperationStatuses(signal)
		if (gr.err) {
			return error(new Error("Getting operation statuses.", {cause: gr.err}))
		}

		let [, res] = gr.v

		return ok(res)
	}

	/**
	 * {@link FilesService.moveBatchItems}
	 */
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

	/**
	 * {@link FilesService.createRoom}
	 */
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

	/**
	 * {@link FilesService.getRoomInfo}
	 */
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

	/**
	 * {@link FilesService.updateRoom}
	 */
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

	/**
	 * {@link FilesService.archiveRoom}
	 */
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

	/**
	 * {@link FilesService.setRoomSecurity}
	 */
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

	/**
	 * {@link FilesService.getRoomSecurityInfo}
	 */
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

	/**
	 * {@link FilesService.getRoomsFolder}
	 */
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
}
