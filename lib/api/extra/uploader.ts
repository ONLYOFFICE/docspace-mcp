/**
 * @module
 * @mergeModuleWith api/extra
 */

import type {Result} from "../../util/result.ts"
import {error, ok} from "../../util/result.ts"
import type * as core from "../core.ts"

const maxChunkSize = 10 * 1024 * 1024 // 10mb

export type UploaderClient = {
	files: UploaderFilesService
}

export type UploaderFilesService = {
	uploadChunk(id: string, chunk: Blob): Promise<Result<[unknown, core.Response], Error>>
}

export class Uploader {
	private client: UploaderClient

	constructor(client: UploaderClient) {
		this.client = client
	}

	async upload(id: string, buf: Uint8Array): Promise<Result<[unknown, core.Response], Error>> {
		let cd: unknown
		let res: core.Response | undefined

		let done = false

		let chunks = Math.ceil(buf.length / maxChunkSize)

		for (let i = 0; i < chunks; i += 1) {
			let s = i * maxChunkSize
			let e = (i + 1) * maxChunkSize
			let c = buf.slice(s, e)
			let b = new Blob([c], {type: "text/plain"})

			let cr = await this.client.files.uploadChunk(id, b)
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
