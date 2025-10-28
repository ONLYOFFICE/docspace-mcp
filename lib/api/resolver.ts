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

import {setTimeout} from "node:timers/promises"
import type * as z from "zod"
import type {Result} from "../util/result.ts"
import {error, ok, safeAsync} from "../util/result.ts"
import type {Response} from "./client.ts"
import type {FileOperationDtoSchema} from "./schemas.ts"

export type Operation = z.output<typeof FileOperationDtoSchema>

class State {
	id: string | undefined
	error: string | undefined
	done = false
}

export interface ResolverClient {
	files: ResolverFilesService
}

export interface ResolverFilesService {
	getOperationStatuses(s: AbortSignal): Promise<Result<[Operation[], Response], Error>>
}

export class Resolver {
	limit = 20
	delay = 100

	private client: ResolverClient

	constructor(client: ResolverClient) {
		this.client = client
	}

	async resolve(signal: AbortSignal, ...ops: Operation[]): Promise<Result<ResolverResponse, Error>> {
		if (ops.length === 0) {
			return error(new Error("No operations to sync."))
		}

		let states: State[] = []

		for (let o of ops) {
			let s = new State()
			s.id = o.id
			s.error = o.error
			s.done = isDone(o)

			states.push(s)
		}

		let limit = this.limit
		let delay = this.delay

		let responses: Response[] = []
		let operations: Operation[] = []

		let err: Error | undefined

		while (limit > 0) {
			let r = await this.client.files.getOperationStatuses(signal)
			if (r.err) {
				err = new Error("Calling operation statuses callback.", {cause: r.err})
				break
			}

			let [ops, res] = r.v

			responses.push(res)

			for (let s of states) {
				if (s.id === undefined) {
					continue
				}

				for (let o of ops) {
					if (o.id === undefined) {
						continue
					}

					if (s.id === o.id) {
						s.error = o.error
						s.done = isDone(o)

						let i = -1

						for (let [j, x] of operations.entries()) {
							if (x.id === o.id) {
								i = j
								break
							}
						}

						if (i !== -1) {
							operations[i] = o
						} else {
							operations.push(o)
						}
					}
				}
			}

			let done = true

			for (let s of states) {
				if (!s.done) {
					done = false
					break
				}
			}

			if (done) {
				break
			}

			limit -= 1

			let t = await safeAsync(setTimeout, delay, undefined, {signal})
			if (t.err) {
				err = new Error("Setting timeout.", {cause: t.err})
				break
			}
		}

		let s = new ResolverResponse()
		s.responses = responses
		s.operations = operations

		let u: string[] = []

		for (let s of states) {
			if (s.id === undefined) {
				continue
			}

			if (s.error !== undefined && s.error !== "" || !s.done) {
				u.push(s.id)
			}
		}

		if (err) {
			let e = new ResolverErrorResponse("Resolving operations.", {cause: err})
			e.response = s
			e.unresolved = u
			return error(e)
		}

		if (u.length !== 0) {
			let m = `${u.length} out of ${ops.length} operations are unresolved.`
			let e = new ResolverErrorResponse(m)
			e.response = s
			e.unresolved = u
			return error(e)
		}

		return ok(s)
	}
}

export class ResolverResponse {
	responses: Response[] = []
	operations: Operation[] = []
}

// eslint-disable-next-line unicorn/custom-error-definition
export class ResolverErrorResponse extends Error {
	response = new ResolverResponse()
	unresolved: string[] = []

	constructor(message: string, options?: ErrorOptions) {
		super(message, options)
		this.name = "ResolverErrorResponse"
	}
}

function isDone(o: Operation): boolean {
	return hasError(o) || isFinished(o)
}

function hasError(o: Operation): boolean {
	return o.error !== undefined && o.error !== ""
}

function isFinished(o: Operation): boolean {
	return o.progress !== undefined && o.progress === 100 ||
		o.finished !== undefined && o.finished
}
