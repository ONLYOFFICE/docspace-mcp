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
import {GetAllFiltersSchema} from "../client/internal/schemas.ts"
// eslint-disable-next-line import-newlines/enforce
import type {
	PeopleService, // eslint-disable-line typescript/no-unused-vars
	Response,
} from "../client.ts"
import type {Server} from "../server.ts"

export const GetAllInputSchema = z.object({
	filters: GetAllFiltersSchema.optional().default({count: 30}).describe("The filters to apply to the list of people. Use them to reduce the size of the response."),
})

export class PeopleToolset {
	private s: Server

	constructor(s: Server) {
		this.s = s
	}

	/**
	 * {@link PeopleService.getAll}
	 */
	async getAll(signal: AbortSignal, p: unknown): Promise<Result<Response, Error>> {
		let pr = GetAllInputSchema.safeParse(p)
		if (!pr.success) {
			return error(new Error("Parsing input.", {cause: pr.error}))
		}

		let gr = await this.s.client.people.getAll(signal, pr.data.filters)
		if (gr.err) {
			return error(new Error("Getting people.", {cause: gr.err}))
		}

		let [, res] = gr.v

		return ok(res)
	}
}
