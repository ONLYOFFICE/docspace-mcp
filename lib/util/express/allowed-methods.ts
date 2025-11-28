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

import type express from "express"

export type AllowedMethodsCallback = (req: express.Request, res: express.Response) => void

export function allowedMethods(methods: string[], cb: AllowedMethodsCallback): express.Handler {
	let am = methods.join(", ")

	return (req, res, next) => {
		if (methods.includes(req.method)) {
			next()
			return
		}

		res.status(405)
		res.set("Allow", am)

		cb(req, res)

		if (!res.writableEnded) {
			res.end()
		}
	}
}
