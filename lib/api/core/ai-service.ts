/**
 * @module
 * @mergeModuleWith api/core
 */

import * as z from "zod"
import type {Result} from "../../util/result.ts"
import {error, ok} from "../../util/result.ts"
import type {Client, Response} from "./client.ts"
import type {VectorizationStartRequestSchema} from "./schemas.ts"
import {AiProfileSchema, AiSettingsDtoSchema} from "./schemas.ts"

// SettingsController: Responses
export type GetAiConfigResponse = z.output<typeof AiSettingsDtoSchema>

// ProfilesController: Responses
export type GetAiProfilesResponseItem = z.output<typeof AiProfileSchema>

// VectorizationController: Options
export type StartVectorizationOptions = z.input<typeof VectorizationStartRequestSchema>

export class AiService {
  private c: Client

  constructor(s: Client) {
    this.c = s
  }

  //
  // SettingsController
  //

  /**
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v4.1.0-server/products/ASC.AI/Server/Api/SettingsController.cs/#L78 | ONLYOFFICE Apps Reference}
   */
  async getConfig(): Promise<Result<[GetAiConfigResponse, Response], Error>> {
    const u = this.c.createUrl("api/2.0/ai/config")
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

    const e = AiSettingsDtoSchema.safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  //
  // ProfilesController
  //

  /**
   * The route returns the profiles without the response envelope.
   *
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v4.1.0-server/common/Tools/ASC.Api.Documentation/ASC.Api.Documentation/json/aichat_2.0.json | ONLYOFFICE Apps Reference}
   */
  async getProfiles(): Promise<Result<[GetAiProfilesResponseItem[], Response], Error>> {
    const u = this.c.createUrl("api/2.0/ai/profiles/list")
    if (u.err) {
      return error(new Error("Creating URL.", {cause: u.err}))
    }

    const req = this.c.createRequest("GET", u.v)
    if (req.err) {
      return error(new Error("Creating request.", {cause: req.err}))
    }

    const f = await this.c.rawFetch(req.v)
    if (f.err) {
      return error(new Error("Fetching request.", {cause: f.err}))
    }

    const [p, res] = f.v

    const e = z.array(AiProfileSchema).safeParse(p)
    if (!e.success) {
      return error(new Error("Parsing response.", {cause: e.error}))
    }

    return ok([e.data, res])
  }

  //
  // VectorizationController
  //

  /**
   * The route returns no data.
   *
   * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v4.1.0-server/products/ASC.AI/Server/Api/VectorizationController.cs/#L52 | ONLYOFFICE Apps Reference}
   */
  async startVectorization(o: StartVectorizationOptions): Promise<Result<Response, Error>> {
    const u = this.c.createUrl("api/2.0/ai/vectorization/tasks")
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
}
