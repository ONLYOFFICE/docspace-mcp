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

import type {Result} from "../util/result.ts"
import {error, ok} from "../util/result.ts"
import type {Response} from "./client.ts"

const maxChunkSize = 10 * 1024 * 1024 // 10mb

export interface UploaderClient {
	files: UploaderFilesService
}

export interface UploaderFilesService {
	uploadChunk(s: AbortSignal, id: string, chunk: Blob): Promise<Result<[unknown, Response], Error>>
}

export class Uploader {
	private client: UploaderClient

	constructor(client: UploaderClient) {
		this.client = client
	}

	async upload(signal: AbortSignal, id: string, buf: Uint8Array): Promise<Result<[unknown, Response], Error>> {
		let cd: unknown
		let res: Response | undefined

		let done = false

		let chunks = Math.ceil(buf.length / maxChunkSize)

		for (let i = 0; i < chunks; i += 1) {
			let s = i * maxChunkSize
			let e = (i + 1) * maxChunkSize
			let c = buf.slice(s, e)
			let b = new Blob([c], {type: "text/plain"})

			let cr = await this.client.files.uploadChunk(signal, id, b)
			if (cr.err) {
				return error(new Error(`Uploading chunk ${i + 1} of ${chunks}.`, {cause: cr.err}))
			}

			[cd, res] = cr.v

			if (res.response.status === 201) {
				done = true
			}

			if (done) {
				break
			}
		}

		if (cd === undefined || res === undefined || !done) {
			return error(new Error("Upload session not completed."))
		}

		return ok([cd, res])
	}
}
