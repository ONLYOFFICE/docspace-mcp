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
		co.origin = o.origin
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
