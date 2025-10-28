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

// This middleware borrowed from:
// https://github.com/go-pkgz/rest/blob/v1.20.4/nocache.go

import type express from "express"

const etagHeaders: string[] = [
	"ETag",
	"If-Modified-Since",
	"If-Match",
	"If-None-Match",
	"If-Range",
	"If-Unmodified-Since",
]

const noCacheHeaders: Record<string, string> = {
	"Expires": new Date(0).toUTCString(),
	"Cache-Control": "no-cache, no-store, no-transform, must-revalidate, private, max-age=0",
	"Pragma": "no-cache",
	"X-Accel-Expires": "0",
}

export function noCache(): express.Handler {
	return (req, res, next) => {
		for (let h of etagHeaders) {
			h = h.toLowerCase()
			if (req.headers[h] !== undefined) {
				// eslint-disable-next-line typescript/no-dynamic-delete
				delete req.headers[h]
			}
		}

		for (let [h, v] of Object.entries(noCacheHeaders)) {
			h = h.toLowerCase()
			res.header(h, v)
		}

		next()
	}
}
