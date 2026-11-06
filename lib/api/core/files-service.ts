/**
 * @module
 * @mergeModuleWith api/core
 */

import * as z from "zod"
import type {Result} from "../../util/result.ts"
import {error, ok, safeNew} from "../../util/result.ts"
import type {Client, Response} from "./client.ts"
import type {
  AiProjectSourcesRequestSchema,
  ArchiveRoomRequestSchema,
  BatchRequestDtoSchema,
  CreateAiRoomRequestDtoSchema,
  CreateFolderFiltersSchema,
  CreateFolderSchema,
  CreateRoomFiltersSchema,
  CreateRoomRequestDtoSchema,
  DeleteFolderSchema,
  DeleteRoomRequestSchema,
  DeleteSchema,
  DocsBuilderRequestDtoSchema,
  DownloadRequestDtoSchema,
  GetAiRoomsFolderFiltersSchema,
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
  UpdateAiProjectModelRequestSchema,
  UpdateFileSchema,
  UpdateRoomFiltersSchema,
  UpdateRoomRequestSchema,
} from "./schemas.ts"
import {
  AiProjectModelDtoSchema,
  AiProjectSourcesDtoSchema,
  AiSkillsDtoSchema,
  FileDtoSchema,
  FileOperationDtoSchema,
  FileShareDtoSchema,
  FilesSettingsDtoSchema,
  FolderContentDtoSchema,
  FolderDtoSchema,
  RoomSecurityDtoSchema,
  UploadSessionObjectDataSchema,
} from "./schemas.ts"

// AiHubController: Options
export type LinkAiProjectSourcesOptions = z.input<typeof AiProjectSourcesRequestSchema>
export type UnlinkAiProjectSourcesOptions = z.input<typeof AiProjectSourcesRequestSchema>
export type UpdateAiProjectModelOptions = z.input<typeof UpdateAiProjectModelRequestSchema>

// AiHubController: Responses
export type GetAiProjectSourcesResponse = z.output<typeof AiProjectSourcesDtoSchema>
export type GetAiRoomSkillsResponse = z.output<typeof AiSkillsDtoSchema>
export type GetAiProjectModelResponse = z.output<typeof AiProjectModelDtoSchema>
export type UpdateAiProjectModelResponse = z.output<typeof AiProjectModelDtoSchema>

// DocsController: Options
export type RunBuilderScriptOptions = z.input<typeof DocsBuilderRequestDtoSchema>

// DocsController: Responses
export type RunBuilderScriptResponse = z.output<typeof FileOperationDtoSchema>

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
export type TerminateOperationResponseItem = z.output<typeof FileOperationDtoSchema>

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
export type CreateAiRoomOptions = z.input<typeof CreateAiRoomRequestDtoSchema>
export type DeleteRoomOptions = z.input<typeof DeleteRoomRequestSchema>
export type SetRoomSecurityOptions = z.input<typeof RoomInvitationRequestSchema>

// VirtualRoomsController: Filters
export type CreateRoomFilters = z.input<typeof CreateRoomFiltersSchema>
export type GetRoomInfoFilters = z.input<typeof GetRoomInfoFiltersSchema>
export type UpdateRoomFilters = z.input<typeof UpdateRoomFiltersSchema>
export type SetRoomSecurityFilters = z.input<typeof SetRoomSecurityFiltersSchema>
export type GetRoomSecurityFilters = z.input<typeof GetRoomSecurityFiltersSchema>
export type GetRoomsFolderFilters = z.input<typeof GetRoomsFolderFiltersSchema>
export type GetAiRoomsFolderFilters = z.input<typeof GetAiRoomsFolderFiltersSchema>

// VirtualRoomsController: Responses
export type CreateRoomResponse = z.output<typeof FolderContentDtoSchema>
export type GetRoomInfoResponse = z.output<typeof FolderDtoSchema>
export type UpdateRoomResponse = z.output<typeof FolderDtoSchema>
export type ArchiveRoomResponse = z.output<typeof FileOperationDtoSchema>
export type CreateAiRoomResponse = z.output<typeof FolderDtoSchema>
export type DeleteRoomResponse = z.output<typeof FileOperationDtoSchema>
export type SetRoomSecurityResponse = z.output<typeof RoomSecurityDtoSchema>
export type GetRoomSecurityInfoResponse = z.output<typeof FileShareDtoSchema>
export type GetRoomFolderResponse = z.output<typeof FolderContentDtoSchema>
export type GetAiRoomsFolderResponse = z.output<typeof FolderContentDtoSchema>

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/tree/v3.0.4-server/products/ASC.Files/ | ONLYOFFICE Apps Reference}
 */
export class FilesService {
  private c: Client

  constructor(s: Client) {
    this.c = s
  }

  //
  // AiHubController
  //

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v4.1.0-server/products/ASC.Files/Server/Api/AiHubController.cs/#L56 | ONLYOFFICE Apps Reference}
   */
  async getAiProjectSources(id: number): Promise<Result<[GetAiProjectSourcesResponse, Response], Error>> {
    const u = this.c.createUrl(`api/2.0/files/rooms/${id}/sources`)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("GET", u.v)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = AiProjectSourcesDtoSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  /**
   * The route returns 204 No Content.
   *
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v4.1.0-server/products/ASC.Files/Server/Api/AiHubController.cs/#L74 | ONLYOFFICE Apps Reference}
   */
  async linkAiProjectSources(id: number, o: LinkAiProjectSourcesOptions): Promise<Result<Response, Error>> {
    const u = this.c.createUrl(`api/2.0/files/rooms/${id}/sources`)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("POST", u.v, o)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.emptyFetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    return ok(f.v)
  }

  /**
   * The route returns 204 No Content.
   *
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v4.1.0-server/products/ASC.Files/Server/Api/AiHubController.cs/#L92 | ONLYOFFICE Apps Reference}
   */
  async unlinkAiProjectSources(id: number, o: UnlinkAiProjectSourcesOptions): Promise<Result<Response, Error>> {
    const u = this.c.createUrl(`api/2.0/files/rooms/${id}/sources`)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("DELETE", u.v, o)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.emptyFetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    return ok(f.v)
  }

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v4.1.0-server/products/ASC.Files/Server/Api/AiHubController.cs/#L109 | ONLYOFFICE Apps Reference}
   */
  async getAiRoomSkills(id: number): Promise<Result<[GetAiRoomSkillsResponse, Response], Error>> {
    const u = this.c.createUrl(`api/2.0/files/rooms/${id}/skills`)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("GET", u.v)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = AiSkillsDtoSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v4.1.0-server/products/ASC.Files/Server/Api/AiHubController.cs/#L143 | ONLYOFFICE Apps Reference}
   */
  async getAiProjectModel(id: number): Promise<Result<[GetAiProjectModelResponse, Response], Error>> {
    const u = this.c.createUrl(`api/2.0/files/rooms/${id}/model`)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("GET", u.v)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = AiProjectModelDtoSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v4.1.0-server/products/ASC.Files/Server/Api/AiHubController.cs/#L161 | ONLYOFFICE Apps Reference}
   */
  async updateAiProjectModel(id: number, o: UpdateAiProjectModelOptions): Promise<Result<[UpdateAiProjectModelResponse, Response], Error>> {
    const u = this.c.createUrl(`api/2.0/files/rooms/${id}/model`)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("PUT", u.v, o)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = AiProjectModelDtoSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  //
  // DocsController
  //

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/develop/products/ASC.Files/Server/Api/DocsController.cs | ONLYOFFICE Apps Reference}
   */
  async runBuilderScript(o: RunBuilderScriptOptions): Promise<Result<[RunBuilderScriptResponse, Response], Error>> {
    const u = this.c.createUrl("api/2.0/docs/builder")
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("POST", u.v, o)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = FileOperationDtoSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  //
  // FilesController
  //

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/FilesController.cs/#L239 | ONLYOFFICE Apps Reference}
   */
  async deleteFile(id: number, o: DeleteFileOptions): Promise<Result<[DeleteFileResponseItem[], Response], Error>> {
    const u = this.c.createUrl(`api/2.0/files/file/${id}`)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("DELETE", u.v, o)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = z.array(FileOperationDtoSchema).safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/FilesController.cs/#L305 | ONLYOFFICE Apps Reference}
   */
  async getFileInfo(id: number, filters?: GetFileInfoFilters): Promise<Result<[GetFileInfoResponse, Response], Error>> {
    const u = this.c.createUrl(`api/2.0/files/file/${id}`, filters)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("GET", u.v)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = FileDtoSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/FilesController.cs/#L399 | ONLYOFFICE Apps Reference}
   */
  async updateFile(id: number, o: UpdateFileOptions): Promise<Result<[UpdateFileResponse, Response], Error>> {
    const u = this.c.createUrl(`api/2.0/files/file/${id}`)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("PUT", u.v, o)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = FileDtoSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  //
  // FoldersController
  //

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/FoldersController.cs/#L110 | ONLYOFFICE Apps Reference}
   */
  async createFolder(id: number, o: CreateFolderOptions, filters?: CreateFolderFilters): Promise<Result<[CreateFolderResponse, Response], Error>> {
    const u = this.c.createUrl(`api/2.0/files/folder/${id}`, filters)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("POST", u.v, o)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = FolderDtoSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/FoldersController.cs/#L126 | ONLYOFFICE Apps Reference}
   */
  async deleteFolder(id: number, o: DeleteFolderOptions): Promise<Result<[DeleteFolderResponseItem[], Response], Error>> {
    const u = this.c.createUrl(`api/2.0/files/folder/${id}`)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("DELETE", u.v, o)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = z.array(FileOperationDtoSchema).safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/FoldersController.cs/#L161 | ONLYOFFICE Apps Reference}
   */
  async getFolder(id: number, filters?: GetFolderFilters): Promise<Result<[GetFolderResponse, Response], Error>> {
    const u = this.c.createUrl(`api/2.0/files/${id}`, filters)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("GET", u.v)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = FolderContentDtoSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/FoldersController.cs/#L180 | ONLYOFFICE Apps Reference}
   */
  async getFolderInfo(id: number, filters?: GetFolderInfoFilters): Promise<Result<[GetFolderInfoResponse, Response], Error>> {
    const u = this.c.createUrl(`api/2.0/files/folder/${id}`, filters)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("GET", u.v)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = FolderDtoSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/FoldersController.cs/#L255 | ONLYOFFICE Apps Reference}
   */
  async renameFolder(id: number, o: RenameFolderOptions, filters?: RenameFolderFilters): Promise<Result<[RenameFolderResponse, Response], Error>> {
    const u = this.c.createUrl(`api/2.0/files/folder/${id}`, filters)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("PUT", u.v, o)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = FolderDtoSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/FoldersController.cs/#L348 | ONLYOFFICE Apps Reference}
   */
  async getMyFolder(filters?: GetMyFolderFilters): Promise<Result<[GetMyFolderResponse, Response], Error>> {
    const u = this.c.createUrl("api/2.0/files/@my", filters)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("GET", u.v)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = FolderContentDtoSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/FoldersController.cs/#L474 | ONLYOFFICE Apps Reference}
   */
  async getTrashFolder(): Promise<Result<[GetFolderResponse, Response], Error>> {
    const u = this.c.createUrl("api/2.0/files/@trash")
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("GET", u.v)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = FolderContentDtoSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  //
  // OperationController
  //

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/OperationController.cs/#L51 | ONLYOFFICE Apps Reference}
   */
  async bulkDownload(o: BulkDownloadOptions): Promise<Result<[BulkDownloadResponseItem[], Response], Error>> {
    const u = this.c.createUrl("api/2.0/files/fileops/bulkdownload")
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("PUT", u.v, o)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = z.array(FileOperationDtoSchema).safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/OperationController.cs/#L74 | ONLYOFFICE Apps Reference}
   */
  async copyBatchItems(o: CopyBatchItemsOptions): Promise<Result<[CopyBatchItemsResponseItem[], Response], Error>> {
    const u = this.c.createUrl("api/2.0/files/fileops/copy")
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("PUT", u.v, o)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = z.array(FileOperationDtoSchema).safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/OperationController.cs/#L136 | ONLYOFFICE Apps Reference}
   */
  async getOperationStatuses(): Promise<Result<[GetOperationStatusesResponseItem[], Response], Error>> {
    const u = this.c.createUrl("api/2.0/files/fileops")
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("GET", u.v)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = z.array(FileOperationDtoSchema).safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/OperationController.cs/#L173 | ONLYOFFICE Apps Reference}
   */
  async moveBatchItems(o: MoveBatchItemsOptions): Promise<Result<[MoveBatchItemsResponseItem[], Response], Error>> {
    const u = this.c.createUrl("api/2.0/files/fileops/move")
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("PUT", u.v, o)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = z.array(FileOperationDtoSchema).safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v4.0.0-server/products/ASC.Files/Server/Api/OperationController.cs/#L514 |ONLYOFFICE Apps Reference}
   */
  async terminateOperation(id: string): Promise<Result<[TerminateOperationResponseItem[], Response], Error>> {
    const u = this.c.createUrl(`api/2.0/files/fileops/terminate/${id}`)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("PUT", u.v)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = z.array(FileOperationDtoSchema).safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  //
  // SettingsController
  //

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.1.1-server/products/ASC.Files/Server/Api/SettingsController.cs/#L199 | ONLYOFFICE Apps Reference}
   */
  async getFilesSettings(): Promise<Result<[GetFilesSettingsResponse, Response], Error>> {
    const u = this.c.createUrl("api/2.0/files/settings")
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("GET", u.v)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = FilesSettingsDtoSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  //
  // UploadController
  //

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/UploadController.cs/#L76 | ONLYOFFICE Apps Reference}
   */
  async createUploadSession(id: number, o: CreateUploadSessionOptions): Promise<Result<[CreateUploadSessionResponse, Response], Error>> {
    const u = this.c.createUrl(`api/2.0/files/${id}/upload/create_session`)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("POST", u.v, o)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = UploadSessionObjectDataSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  //
  // VirtualRoomsController
  //

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/VirtualRoomsController.cs/#L70 | ONLYOFFICE Apps Reference}
   */
  async createRoom(o: CreateRoomOptions, filters?: CreateRoomFilters): Promise<Result<[CreateRoomResponse, Response], Error>> {
    const u = this.c.createUrl("api/2.0/files/rooms", filters)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("POST", u.v, o)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = FolderContentDtoSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/VirtualRoomsController.cs/#L165 | ONLYOFFICE Apps Reference}
   */
  async getRoomInfo(id: number, filters?: GetRoomInfoFilters): Promise<Result<[GetRoomInfoResponse, Response], Error>> {
    const u = this.c.createUrl(`api/2.0/files/rooms/${id}`, filters)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("GET", u.v)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = FolderDtoSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/VirtualRoomsController.cs/#L180 | ONLYOFFICE Apps Reference}
   */
  async updateRoom(id: number, o: UpdateRoomOptions, filters?: UpdateRoomFilters): Promise<Result<[UpdateRoomResponse, Response], Error>> {
    const u = this.c.createUrl(`api/2.0/files/rooms/${id}`, filters)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("PUT", u.v, o)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = FolderDtoSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/VirtualRoomsController.cs/#L275 | ONLYOFFICE Apps Reference}
   */
  async archiveRoom(id: number, o: ArchiveRoomOptions): Promise<Result<[ArchiveRoomResponse, Response], Error>> {
    const u = this.c.createUrl(`api/2.0/files/rooms/${id}/archive`)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("PUT", u.v, o)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = FileOperationDtoSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/VirtualRoomsController.cs/#L311 | ONLYOFFICE Apps Reference}
   */
  async setRoomSecurity(id: number, o: SetRoomSecurityOptions, filters?: SetRoomSecurityFilters): Promise<Result<[SetRoomSecurityResponse, Response], Error>> {
    const u = this.c.createUrl(`api/2.0/files/rooms/${id}/share`, filters)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("PUT", u.v, o)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = RoomSecurityDtoSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/VirtualRoomsController.cs/#L349 | ONLYOFFICE Apps Reference}
   */
  async getRoomSecurityInfo(id: number, filters?: GetRoomSecurityFilters): Promise<Result<[GetRoomSecurityInfoResponse[], Response], Error>> {
    const u = this.c.createUrl(`api/2.0/files/rooms/${id}/share`, filters)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("GET", u.v)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = z.array(FileShareDtoSchema).safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Api/VirtualRoomsController.cs/#L649 | ONLYOFFICE Apps Reference}
   */
  async getRoomsFolder(filters?: GetRoomsFolderFilters): Promise<Result<[GetRoomFolderResponse, Response], Error>> {
    const u = this.c.createUrl("api/2.0/files/rooms", filters)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("GET", u.v)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = FolderContentDtoSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  /**
   * Creates an instructions room, a knowledge room or an AI project in the AI rooms
   * section.
   *
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v4.1.0-server/products/ASC.Files/Server/Api/VirtualRoomsController.cs/#L107 | ONLYOFFICE Apps Reference}
   */
  async createAiRoom(o: CreateAiRoomOptions, filters?: CreateRoomFilters): Promise<Result<[CreateAiRoomResponse, Response], Error>> {
    const u = this.c.createUrl("api/2.0/files/rooms", filters)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("POST", u.v, o)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = FolderDtoSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  /**
   * Deletes a room permanently, without moving it to the trash.
   *
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v4.1.0-server/products/ASC.Files/Server/Api/VirtualRoomsController.cs/#L617 | ONLYOFFICE Apps Reference}
   */
  async deleteRoom(id: number, o: DeleteRoomOptions): Promise<Result<[DeleteRoomResponse, Response], Error>> {
    const u = this.c.createUrl(`api/2.0/files/rooms/${id}`)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("DELETE", u.v, o)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = FileOperationDtoSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  /**
   * Gets the AI rooms section.
   *
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v4.1.0-server/products/ASC.Files/Server/Api/VirtualRoomsController.cs/#L1363 | ONLYOFFICE Apps Reference}
   */
  async getAiRoomsFolder(filters?: GetAiRoomsFolderFilters): Promise<Result<[GetAiRoomsFolderResponse, Response], Error>> {
    const u = this.c.createUrl("api/2.0/files/rooms", {...filters, searchArea: "AiHub"})
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("GET", u.v)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = FolderContentDtoSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  //
  // Others
  //

  /**
   * Downloads the original content of a file, without converting it.
   *
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v4.1.0-server/products/ASC.Files/Core/HttpHandlers/FileHandler.ashx.cs/#L117 | ONLYOFFICE Apps Reference}
   */
  async downloadFile(id: number): Promise<Result<Response, Error>> {
    const u = this.c.createUrl("filehandler.ashx", {action: "download", fileid: id})
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("GET", u.v)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fileFetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    return ok(f.v)
  }

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.Files/Server/Startup.cs/#L76 | ONLYOFFICE Apps Reference}
   */
  async uploadChunk(id: string, chunk: Blob): Promise<Result<[unknown, Response], Error>> {
    const u = this.c.createUrl(`ChunkedUploader.ashx?uid=${id}`)
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const d = safeNew(FormData)
    if (d.err) {
      return error(new Error("Creating FormData.", {cause: d.err}))
    }

    d.v.append("file", chunk)

    const req = this.c.createFormRequest(u.v, d.v)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.fetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    return ok(f.v)
  }
}
