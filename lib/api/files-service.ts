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
import type {Result} from "../util/result.ts"
import {error, ok, safeNew} from "../util/result.ts"
import type {Client, Response} from "./client.ts"
import type {
	ArchiveRoomRequestSchema,
	BatchRequestDtoSchema,
	CreateFolderFiltersSchema,
	CreateFolderSchema,
	CreateRoomFiltersSchema,
	CreateRoomRequestDtoSchema,
	DeleteFolderSchema,
	DeleteSchema,
	DownloadRequestDtoSchema,
	GetFileInfoFiltersSchema,
	GetFolderFiltersSchema,
	GetFolderInfoFiltersSchema,
	GetMyFolderFiltersSchema,
	GetRoomInfoFiltersSchema,
	GetRoomSecurityFiltersSchema,
	GetRoomsFolderFiltersSchema,
	RenameFolderFiltersSchema,
	RoomInvitationRequestSchema,
	SessionRequestSchema,
	SetRoomSecurityFiltersSchema,
	UpdateFileSchema,
	UpdateRoomFiltersSchema,
	UpdateRoomRequestSchema,
} from "./schemas.ts"
import {
	FileDtoSchema,
	FileOperationDtoSchema,
	FileShareDtoSchema,
	FilesSettingsDtoSchema,
	FolderContentDtoSchema,
	FolderDtoSchema,
	RoomSecurityDtoSchema,
	UploadSessionObjectDataSchema,
} from "./schemas.ts"

// FilesController: Options
export type DeleteFileOptions = z.input<typeof DeleteSchema>
export type UpdateFileOptions = z.input<typeof UpdateFileSchema>

// FilesController: Filters
export type GetFileInfoFilters = z.input<typeof GetFileInfoFiltersSchema>

// FilesController: Responses
export type DeleteFileResponseItem = z.output<typeof FileOperationDtoSchema>
export type GetFileInfoResponse = z.output<typeof FileDtoSchema>
export type UpdateFileResponse = z.output<typeof FileDtoSchema>

// FoldersController: Options
export type CreateFolderOptions = z.input<typeof CreateFolderSchema>
export type DeleteFolderOptions = z.input<typeof DeleteFolderSchema>
export type RenameFolderOptions = z.input<typeof CreateFolderSchema>

// FoldersController: Filters
export type CreateFolderFilters = z.input<typeof CreateFolderFiltersSchema>
export type GetFolderFilters = z.input<typeof GetFolderFiltersSchema>
export type GetFolderInfoFilters = z.input<typeof GetFolderInfoFiltersSchema>
export type RenameFolderFilters = z.input<typeof RenameFolderFiltersSchema>
export type GetMyFolderFilters = z.input<typeof GetMyFolderFiltersSchema>

// FoldersController: Responses
export type CreateFolderResponse = z.output<typeof FolderDtoSchema>
export type DeleteFolderResponseItem = z.output<typeof FileOperationDtoSchema>
export type GetFolderResponse = z.output<typeof FolderContentDtoSchema>
export type GetFolderInfoResponse = z.output<typeof FolderDtoSchema>
export type RenameFolderResponse = z.output<typeof FolderDtoSchema>
export type GetMyFolderResponse = z.output<typeof FolderContentDtoSchema>

// OperationController: Options
export type BulkDownloadOptions = z.output<typeof DownloadRequestDtoSchema>
export type CopyBatchItemsOptions = z.input<typeof BatchRequestDtoSchema>
export type MoveBatchItemsOptions = z.input<typeof BatchRequestDtoSchema>

// OperationController: Responses
export type BulkDownloadResponseItem = z.output<typeof FileOperationDtoSchema>
export type CopyBatchItemsResponseItem = z.output<typeof FileOperationDtoSchema>
export type GetOperationStatusesResponseItem = z.output<typeof FileOperationDtoSchema>
export type MoveBatchItemsResponseItem = z.output<typeof FileOperationDtoSchema>

// SettingsController: Responses
export type GetFilesSettingsResponse = z.output<typeof FilesSettingsDtoSchema>

// UploadController: Options
export type CreateUploadSessionOptions = z.output<typeof SessionRequestSchema>

// UploadController: Responses
export type CreateUploadSessionResponse = z.output<typeof UploadSessionObjectDataSchema>

// VirtualRoomsController: Options
export type CreateRoomOptions = z.input<typeof CreateRoomRequestDtoSchema>
export type UpdateRoomOptions = z.input<typeof UpdateRoomRequestSchema>
export type ArchiveRoomOptions = z.input<typeof ArchiveRoomRequestSchema>
export type SetRoomSecurityOptions = z.input<typeof RoomInvitationRequestSchema>

// VirtualRoomsController: Filters
export type CreateRoomFilters = z.input<typeof CreateRoomFiltersSchema>
export type GetRoomInfoFilters = z.input<typeof GetRoomInfoFiltersSchema>
export type UpdateRoomFilters = z.input<typeof UpdateRoomFiltersSchema>
export type SetRoomSecurityFilters = z.input<typeof SetRoomSecurityFiltersSchema>
export type GetRoomSecurityFilters = z.input<typeof GetRoomSecurityFiltersSchema>
export type GetRoomsFolderFilters = z.input<typeof GetRoomsFolderFiltersSchema>

// VirtualRoomsController: Responses
export type CreateRoomResponse = z.output<typeof FolderContentDtoSchema>
export type GetRoomInfoResponse = z.output<typeof FolderDtoSchema>
export type UpdateRoomResponse = z.output<typeof FolderDtoSchema>
export type ArchiveRoomResponse = z.output<typeof FileOperationDtoSchema>
export type SetRoomSecurityResponse = z.output<typeof RoomSecurityDtoSchema>
export type GetRoomSecurityInfoResponse = z.output<typeof FileShareDtoSchema>
export type GetRoomFolderResponse = z.output<typeof FolderContentDtoSchema>

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/tree/v3.0.4-server/products/ASC.Files/ | DocSpace Reference}
 */
export class FilesService {
	private c: Client

	constructor(s: Client) {
		this.c = s
	}

	//
	// FilesController
	//

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/FilesController.cs/#L239 | DocSpace Reference}
	 */
	async deleteFile(s: AbortSignal, id: number, o: DeleteFileOptions): Promise<Result<[DeleteFileResponseItem[], Response], Error>> {
		let u = this.c.createSharedUrl(`api/2.0/files/file/${id}`)
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "DELETE", u.v, o)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.sharedFetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let [p, res] = f.v

		let e = z.array(FileOperationDtoSchema).safeParse(p)
		if (!e.success) {
			return error(new Error("Parsing response.", {cause: e.error}))
		}

		return ok([e.data, res])
	}

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/FilesController.cs/#L305 | DocSpace Reference}
	 */
	async getFileInfo(s: AbortSignal, id: number, filters?: GetFileInfoFilters): Promise<Result<[GetFileInfoResponse, Response], Error>> {
		let u = this.c.createSharedUrl(`api/2.0/files/file/${id}`, filters)
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "GET", u.v)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.sharedFetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let [p, res] = f.v

		let e = FileDtoSchema.safeParse(p)
		if (!e.success) {
			return error(new Error("Parsing response.", {cause: e.error}))
		}

		return ok([e.data, res])
	}

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/FilesController.cs/#L399 | DocSpace Reference}
	 */
	async updateFile(s: AbortSignal, id: number, o: UpdateFileOptions): Promise<Result<[UpdateFileResponse, Response], Error>> {
		let u = this.c.createSharedUrl(`api/2.0/files/file/${id}`)
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "PUT", u.v, o)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.sharedFetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let [p, res] = f.v

		let e = FileDtoSchema.safeParse(p)
		if (!e.success) {
			return error(new Error("Parsing response.", {cause: e.error}))
		}

		return ok([e.data, res])
	}

	//
	// FoldersController
	//

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/FoldersController.cs/#L110 | DocSpace Reference}
	 */
	async createFolder(s: AbortSignal, id: number, o: CreateFolderOptions, filters?: CreateFolderFilters): Promise<Result<[CreateFolderResponse, Response], Error>> {
		let u = this.c.createSharedUrl(`api/2.0/files/folder/${id}`, filters)
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "POST", u.v, o)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.sharedFetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let [p, res] = f.v

		let e = FolderDtoSchema.safeParse(p)
		if (!e.success) {
			return error(new Error("Parsing response.", {cause: e.error}))
		}

		return ok([e.data, res])
	}

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/FoldersController.cs/#L126 | DocSpace Reference}
	 */
	async deleteFolder(s: AbortSignal, id: number, o: DeleteFolderOptions): Promise<Result<[DeleteFolderResponseItem[], Response], Error>> {
		let u = this.c.createSharedUrl(`api/2.0/files/folder/${id}`)
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "DELETE", u.v, o)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.sharedFetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let [p, res] = f.v

		let e = z.array(FileOperationDtoSchema).safeParse(p)
		if (!e.success) {
			return error(new Error("Parsing response.", {cause: e.error}))
		}

		return ok([e.data, res])
	}

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/FoldersController.cs/#L161 | DocSpace Reference}
	 */
	async getFolder(s: AbortSignal, id: number, filters?: GetFolderFilters): Promise<Result<[GetFolderResponse, Response], Error>> {
		let u = this.c.createSharedUrl(`api/2.0/files/${id}`, filters)
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "GET", u.v)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.sharedFetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let [p, res] = f.v

		let e = FolderContentDtoSchema.safeParse(p)
		if (!e.success) {
			return error(new Error("Parsing response.", {cause: e.error}))
		}

		return ok([e.data, res])
	}

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/FoldersController.cs/#L180 | DocSpace Reference}
	 */
	async getFolderInfo(s: AbortSignal, id: number, filters?: GetFolderInfoFilters): Promise<Result<[GetFolderInfoResponse, Response], Error>> {
		let u = this.c.createSharedUrl(`api/2.0/files/folder/${id}`, filters)
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "GET", u.v)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.sharedFetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let [p, res] = f.v

		let e = FolderDtoSchema.safeParse(p)
		if (!e.success) {
			return error(new Error("Parsing response.", {cause: e.error}))
		}

		return ok([e.data, res])
	}

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/FoldersController.cs/#L255 | DocSpace Reference}
	 */
	async renameFolder(s: AbortSignal, id: number, o: RenameFolderOptions, filters?: RenameFolderFilters): Promise<Result<[RenameFolderResponse, Response], Error>> {
		let u = this.c.createSharedUrl(`api/2.0/files/folder/${id}`, filters)
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "PUT", u.v, o)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.sharedFetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let [p, res] = f.v

		let e = FolderDtoSchema.safeParse(p)
		if (!e.success) {
			return error(new Error("Parsing response.", {cause: e.error}))
		}

		return ok([e.data, res])
	}

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/FoldersController.cs/#L348 | DocSpace Reference}
	 */
	async getMyFolder(s: AbortSignal, filters?: GetMyFolderFilters): Promise<Result<[GetMyFolderResponse, Response], Error>> {
		let u = this.c.createSharedUrl("api/2.0/files/@my", filters)
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "GET", u.v)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.sharedFetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let [p, res] = f.v

		let e = FolderContentDtoSchema.safeParse(p)
		if (!e.success) {
			return error(new Error("Parsing response.", {cause: e.error}))
		}

		return ok([e.data, res])
	}

	//
	// OperationController
	//

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/OperationController.cs/#L51 | DocSpace Reference}
	 */
	async bulkDownload(s: AbortSignal, o: BulkDownloadOptions): Promise<Result<[BulkDownloadResponseItem[], Response], Error>> {
		let u = this.c.createSharedUrl("api/2.0/files/fileops/bulkdownload")
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "PUT", u.v, o)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.sharedFetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let [p, res] = f.v

		let e = z.array(FileOperationDtoSchema).safeParse(p)
		if (!e.success) {
			return error(new Error("Parsing response.", {cause: e.error}))
		}

		return ok([e.data, res])
	}

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/OperationController.cs/#L74 | DocSpace Reference}
	 */
	async copyBatchItems(s: AbortSignal, o: CopyBatchItemsOptions): Promise<Result<[CopyBatchItemsResponseItem[], Response], Error>> {
		let u = this.c.createSharedUrl("api/2.0/files/fileops/copy")
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "PUT", u.v, o)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.sharedFetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let [p, res] = f.v

		let e = z.array(FileOperationDtoSchema).safeParse(p)
		if (!e.success) {
			return error(new Error("Parsing response.", {cause: e.error}))
		}

		return ok([e.data, res])
	}

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/OperationController.cs/#L136 | DocSpace Reference}
	 */
	async getOperationStatuses(s: AbortSignal): Promise<Result<[GetOperationStatusesResponseItem[], Response], Error>> {
		let u = this.c.createSharedUrl("api/2.0/files/fileops")
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "GET", u.v)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.sharedFetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let [p, res] = f.v

		let e = z.array(FileOperationDtoSchema).safeParse(p)
		if (!e.success) {
			return error(new Error("Parsing response.", {cause: e.error}))
		}

		return ok([e.data, res])
	}

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/OperationController.cs/#L173 | DocSpace Reference}
	 */
	async moveBatchItems(s: AbortSignal, o: MoveBatchItemsOptions): Promise<Result<[MoveBatchItemsResponseItem[], Response], Error>> {
		let u = this.c.createSharedUrl("api/2.0/files/fileops/move")
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "PUT", u.v, o)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.sharedFetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let [p, res] = f.v

		let e = z.array(FileOperationDtoSchema).safeParse(p)
		if (!e.success) {
			return error(new Error("Parsing response.", {cause: e.error}))
		}

		return ok([e.data, res])
	}

	//
	// SettingsController
	//

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Server/Api/SettingsController.cs/#L199 | DocSpace Reference}
	 */
	async getFilesSettings(s: AbortSignal): Promise<Result<[GetFilesSettingsResponse, Response], Error>> {
		let u = this.c.createSharedUrl("api/2.0/files/settings")
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "GET", u.v)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.sharedFetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let [p, res] = f.v

		let e = FilesSettingsDtoSchema.safeParse(p)
		if (!e.success) {
			return error(new Error("Parsing response.", {cause: e.error}))
		}

		return ok([e.data, res])
	}

	//
	// UploadController
	//

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/UploadController.cs/#L76 | DocSpace Reference}
	 */
	async createUploadSession(s: AbortSignal, id: number, o: CreateUploadSessionOptions): Promise<Result<[CreateUploadSessionResponse, Response], Error>> {
		let u = this.c.createSharedUrl(`api/2.0/files/${id}/upload/create_session`)
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "POST", u.v, o)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.sharedFetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let [p, res] = f.v

		let e = UploadSessionObjectDataSchema.safeParse(p)
		if (!e.success) {
			return error(new Error("Parsing response.", {cause: e.error}))
		}

		return ok([e.data, res])
	}

	//
	// VirtualRoomsController
	//

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/VirtualRoomsController.cs/#L70 | DocSpace Reference}
	 */
	async createRoom(s: AbortSignal, o: CreateRoomOptions, filters?: CreateRoomFilters): Promise<Result<[CreateRoomResponse, Response], Error>> {
		let u = this.c.createSharedUrl("api/2.0/files/rooms", filters)
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "POST", u.v, o)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.sharedFetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let [p, res] = f.v

		let e = FolderContentDtoSchema.safeParse(p)
		if (!e.success) {
			return error(new Error("Parsing response.", {cause: e.error}))
		}

		return ok([e.data, res])
	}

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/VirtualRoomsController.cs/#L165 | DocSpace Reference}
	 */
	async getRoomInfo(s: AbortSignal, id: number, filters?: GetRoomInfoFilters): Promise<Result<[GetRoomInfoResponse, Response], Error>> {
		let u = this.c.createSharedUrl(`api/2.0/files/rooms/${id}`, filters)
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "GET", u.v)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.sharedFetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let [p, res] = f.v

		let e = FolderDtoSchema.safeParse(p)
		if (!e.success) {
			return error(new Error("Parsing response.", {cause: e.error}))
		}

		return ok([e.data, res])
	}

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/VirtualRoomsController.cs/#L180 | DocSpace Reference}
	 */
	async updateRoom(s: AbortSignal, id: number, o: UpdateRoomOptions, filters?: UpdateRoomFilters): Promise<Result<[UpdateRoomResponse, Response], Error>> {
		let u = this.c.createSharedUrl(`api/2.0/files/rooms/${id}`, filters)
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "PUT", u.v, o)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.sharedFetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let [p, res] = f.v

		let e = FolderDtoSchema.safeParse(p)
		if (!e.success) {
			return error(new Error("Parsing response.", {cause: e.error}))
		}

		return ok([e.data, res])
	}

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/VirtualRoomsController.cs/#L275 | DocSpace Reference}
	 */
	async archiveRoom(s: AbortSignal, id: number, o: ArchiveRoomOptions): Promise<Result<[ArchiveRoomResponse, Response], Error>> {
		let u = this.c.createSharedUrl(`api/2.0/files/rooms/${id}/archive`)
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "PUT", u.v, o)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.sharedFetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let [p, res] = f.v

		let e = FileOperationDtoSchema.safeParse(p)
		if (!e.success) {
			return error(new Error("Parsing response.", {cause: e.error}))
		}

		return ok([e.data, res])
	}

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/VirtualRoomsController.cs/#L311 | DocSpace Reference}
	 */
	async setRoomSecurity(s: AbortSignal, id: number, o: SetRoomSecurityOptions, filters?: SetRoomSecurityFilters): Promise<Result<[SetRoomSecurityResponse, Response], Error>> {
		let u = this.c.createSharedUrl(`api/2.0/files/rooms/${id}/share`, filters)
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "PUT", u.v, o)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.sharedFetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let [p, res] = f.v

		let e = RoomSecurityDtoSchema.safeParse(p)
		if (!e.success) {
			return error(new Error("Parsing response.", {cause: e.error}))
		}

		return ok([e.data, res])
	}

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/VirtualRoomsController.cs/#L349 | DocSpace Reference}
	 */
	async getRoomSecurityInfo(s: AbortSignal, id: number, filters?: GetRoomSecurityFilters): Promise<Result<[GetRoomSecurityInfoResponse[], Response], Error>> {
		let u = this.c.createSharedUrl(`api/2.0/files/rooms/${id}/share`, filters)
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "GET", u.v)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.sharedFetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let [p, res] = f.v

		let e = z.array(FileShareDtoSchema).safeParse(p)
		if (!e.success) {
			return error(new Error("Parsing response.", {cause: e.error}))
		}

		return ok([e.data, res])
	}

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/VirtualRoomsController.cs/#L649 | DocSpace Reference}
	 */
	async getRoomsFolder(s: AbortSignal, filters?: GetRoomsFolderFilters): Promise<Result<[GetRoomFolderResponse, Response], Error>> {
		let u = this.c.createSharedUrl("api/2.0/files/rooms", filters)
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "GET", u.v)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.sharedFetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let [p, res] = f.v

		let e = FolderContentDtoSchema.safeParse(p)
		if (!e.success) {
			return error(new Error("Parsing response.", {cause: e.error}))
		}

		return ok([e.data, res])
	}

	//
	// Others
	//

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Startup.cs/#L76 | DocSpace Reference}
	 */
	async uploadChunk(s: AbortSignal, id: string, chunk: Blob): Promise<Result<[unknown, Response], Error>> {
		let u = this.c.createSharedUrl(`ChunkedUploader.ashx?uid=${id}`)
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let d = safeNew(FormData)
		if (d.err) {
			return error(new Error("Creating FormData.", {cause: d.err}))
		}

		d.v.append("file", chunk)

		let req = this.c.createFormRequest(s, u.v, d.v)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.sharedFetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		return ok(f.v)
	}
}
