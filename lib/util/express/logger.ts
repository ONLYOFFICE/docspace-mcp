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
import type * as context from "../context.ts"

const outgoing = "<--"
const incoming = "-->"

interface Payload {
	sessionId?: string
	method?: string
	url?: string
	status?: number
	duration?: string
}

export interface ContextProvider {
	get(): context.Context | undefined
}

export interface Logger {
	info(msg: string, o?: object): void
	warn(msg: string, o?: object): void
	error(msg: string, o?: object): void
}

export function logger(p: ContextProvider, l: Logger): express.Handler {
	return (req, res, next) => {
		let o: Payload = {}

		let c = p.get()
		if (c && c.sessionId) {
			o.sessionId = c.sessionId
		}

		o.method = req.method
		o.url = req.url

		l.info(incoming, o)

		let s = Date.now()

		res.on("finish", () => {
			o.status = res.statusCode

			let d = Date.now() - s
			if (d < 1000) {
				o.duration = `${d}ms`
			} else {
				o.duration = `${Math.round(d / 1000)}s`
			}

			l.info(outgoing, o)
		})

		next()
	}
}
