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
 * @mergeModuleWith util/logger
 */

import logfmt from "logfmt"
import * as errors from "../errors.ts"
import * as strings from "../strings.ts"

export interface Writable {
	write(data: string): void
}

export class VanillaLogger {
	private w: Writable

	constructor(w: Writable) {
		this.w = w
	}

	info(msg: string, o?: object): void {
		this.log("INF", msg, o)
	}

	warn(msg: string, o?: object): void {
		this.log("WRN", msg, o)
	}

	error(msg: string, o?: object): void {
		this.log("ERR", msg, o)
	}

	mute(): void {
		this.log = () => {}
	}

	private log(level: string, msg: string, o?: object): void {
		let v: object = {time: new Date().toISOString(), level, msg, ...o}
		let r = format(v)
		logfmt.log(r, this.w)
	}
}

function format(v: object): Record<string, unknown> {
	let s: Record<string, unknown> = {}
	for (let [p, e] of Object.entries(v)) {
		next(s, p, e)
	}
	return s

	function next(o: Record<string, unknown>, k: string, v: unknown): void {
		if (v === null || v === undefined) {
			return
		}

		if (typeof v === "boolean" || typeof v === "number") {
			o[strings.camelCaseToSnakeCase(k)] = v
			return
		}

		if (typeof v === "string") {
			o[strings.camelCaseToSnakeCase(k)] = strings.escapeWhitespace(v)
			return
		}

		if (Array.isArray(v)) {
			for (let [i, e] of v.entries()) {
				next(o, `${k}[${i}]`, e)
			}
			return
		}

		if (v instanceof Error) {
			let m = errors.format(v)
			o[strings.camelCaseToSnakeCase(k)] = strings.escapeWhitespace(m)
			return
		}

		if (typeof v === "object") {
			for (let [p, e] of Object.entries(v)) {
				next(o, `${k}.${p}`, e)
			}
			return
		}
	}
}
