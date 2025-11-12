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
 * @mergeModuleWith oauth
 */

import * as errors from "../util/errors.ts"
import {ClientErrorResponse} from "./client.ts"
import type {ErrorResponse} from "./shared.ts"

export function proxyError(ce: Error, fe: Error): [number, ErrorResponse] {
	let code: number | undefined
	let error: string | undefined
	let error_description: string | undefined
	let error_uri: string | undefined

	let cr = errors.as(ce, ClientErrorResponse)
	if (cr) {
		code = cr.response.status
		error = cr.error
		error_description = cr.error_description
		error_uri = cr.error_uri
	} else {
		code = 500
		error = "server_error"
		error_description = errors.format(fe)
	}

	let er: ErrorResponse = {
		error,
	}

	if (error_description) {
		er.error_description = error_description
	}

	if (error_uri) {
		er.error_uri = error_uri
	}

	return [code, er]
}
