/**
 * @module
 * @mergeModuleWith util/express
 */

import contentType from "content-type"
import type express from "express"
import * as r from "../result.ts"

export type SupportedMediaTypesCallback = (req: express.Request, res: express.Response) => void

export function supportedMediaTypes(types: string[], cb: SupportedMediaTypesCallback): express.Handler {
	let st = types.join(", ")

	return (req, res, next) => {
		let ct = r.safeSync(contentType.parse, req)
		if (!ct.err && types.includes(ct.v.type)) {
			next()
			return
		}

		res.status(415)
		res.set("Accept", st)

		cb(req, res)

		if (!res.writableEnded) {
			res.end()
		}
	}
}
