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
 * @module util/express
 */

/* eslint-disable typescript/consistent-type-definitions */

import type express from "express"
import * as expressRateLimit from "express-rate-limit"

export const rateLimitHeaders: string[] = [
	"Retry-After",
	"RateLimit-Limit",
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
