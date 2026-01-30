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
