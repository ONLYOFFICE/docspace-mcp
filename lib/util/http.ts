/**
 * @module util/http
 */

import type http from "node:http"

export function header(req: http.IncomingMessage, key: string): string {
	let h = req.headers[key.toLowerCase()]

	if (!h || h.length === 0) {
		return ""
	}

	if (Array.isArray(h)) {
		return h[0]
	}

	return h
}
