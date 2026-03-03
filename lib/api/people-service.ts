/**
 * @module
 * @mergeModuleWith api
 */

import * as z from "zod"
import type {Result} from "../util/result.ts"
import {error, ok} from "../util/result.ts"
import type {Client, Response} from "./client.ts"
import type {GetFullByFilterFiltersSchema} from "./schemas.ts"
import {EmployeeFullDtoSchema} from "./schemas.ts"

export type GetFullByFilterFilters = z.input<typeof GetFullByFilterFiltersSchema>
export type GetFullByFilterResponseItem = z.output<typeof EmployeeFullDtoSchema>

/**
 * {@link https://github.com/ONLYOFFICE/DocSpace-server/tree/v3.0.4-server/products/ASC.People/ | DocSpace Reference}
 */
export class PeopleService {
	private c: Client

	constructor(s: Client) {
		this.c = s
	}

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/products/ASC.People/Server/Api/UserController.cs/#L811 | DocSpace Reference}
	 */
	async getFullByFilter(filters?: GetFullByFilterFilters): Promise<Result<[GetFullByFilterResponseItem[], Response], Error>> {
		let u = this.c.createUrl("api/2.0/people/filter", filters)
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest("GET", u.v)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.fetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		let [p, res] = f.v

		let e = z.array(EmployeeFullDtoSchema).safeParse(p)
		if (!e.success) {
			return error(new Error("Parsing response.", {cause: e.error}))
		}

		return ok([e.data, res])
	}
}
