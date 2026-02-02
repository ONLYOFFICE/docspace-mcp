/**
 * @module
 * @mergeModuleWith util/express
 */

import cors_ from "cors"
import type express from "express"

export type CorsOptions = {
	origin: string[]
	maxAge: number
	methods: string[]
	allowedHeaders: string[]
	exposedHeaders: string[]
}

export function cors(o: CorsOptions): express.Handler {
	let co: cors_.CorsOptions = {}

	if (o.origin.length !== 0) {
		if (o.origin.includes("*")) {
			co.origin = "*"
		} else {
			co.origin = [...new Set(o.origin)].sort()
		}
	}

	if (o.methods.length !== 0) {
		co.methods = o.methods
	}

	if (o.allowedHeaders.length !== 0) {
		co.allowedHeaders = [...new Set(o.allowedHeaders)].sort()
	}

	if (o.exposedHeaders.length !== 0) {
		co.exposedHeaders = [...new Set(o.exposedHeaders)].sort()
	}

	if (o.maxAge) {
		co.maxAge = o.maxAge / 1000
	}

	return cors_(co)
}
