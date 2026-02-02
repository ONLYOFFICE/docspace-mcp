/**
 * @module
 * @mergeModuleWith util/express
 */

import type express from "express"
import * as expressRateLimit from "express-rate-limit"

export const rateLimitHeaders: string[] = [
	"Retry-After",
	"RateLimit-Limit",
	"RateLimit-Policy",
	"RateLimit-Remaining",
	"RateLimit-Reset",
]

export type RateLimitOptions = {
	capacity: number
	window: number
}

export type RateLimitCallback = (req: express.Request, res: express.Response) => void

export function rateLimit(o: RateLimitOptions, cb: RateLimitCallback): express.Handler {
	let ro: Partial<expressRateLimit.Options> = {
		windowMs: o.window,
		limit: o.capacity,
		standardHeaders: true,
		legacyHeaders: false,
		message: cb,
	}

	return expressRateLimit.rateLimit(ro)
}
