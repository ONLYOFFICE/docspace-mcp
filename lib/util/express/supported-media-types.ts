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
