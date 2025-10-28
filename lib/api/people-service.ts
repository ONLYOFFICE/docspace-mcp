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
import {error, ok} from "../util/result.ts"
import type {Client, Response} from "./client.ts"
import type {GetAllFiltersSchema} from "./schemas.ts"
import {EmployeeDtoSchema} from "./schemas.ts"

export type GetAllFilters = z.input<typeof GetAllFiltersSchema>
export type GetAllResponseItem = z.output<typeof EmployeeDtoSchema>

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/tree/v3.0.4-server/products/ASC.People/ | DocSpace Reference}
 */
export class PeopleService {
	private c: Client

	constructor(s: Client) {
		this.c = s
	}

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.People/Server/Api/UserController.cs/#L681 | DocSpace Reference}
	 */
	async getAll(s: AbortSignal, filters?: GetAllFilters): Promise<Result<[GetAllResponseItem[], Response], Error>> {
		let u = this.c.createUrl("api/2.0/people", filters)
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "GET", u.v)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.fetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let [p, res] = f.v

		let e = z.array(EmployeeDtoSchema).safeParse(p)
		if (!e.success) {
			return error(new Error("Parsing response.", {cause: e.error}))
		}

		return ok([e.data, res])
	}
}
