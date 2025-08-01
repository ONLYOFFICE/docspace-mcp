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

import {existsSync} from "node:fs"

const envs = new Set<string>([
	"HTTP_PROXY",
	"DOCSPACE_BASE_URL",
	"DOCSPACE_ORIGIN",
	"DOCSPACE_USER_AGENT",
	"DOCSPACE_API_KEY",
	"DOCSPACE_AUTH_TOKEN",
	"DOCSPACE_USERNAME",
	"DOCSPACE_PASSWORD",
	"DOCSPACE_DYNAMIC",
	"DOCSPACE_TOOLSETS",
])

export function load(): void {
	if (existsSync(".env")) {
		process.loadEnvFile(".env")
	}

	// https://github.com/modelcontextprotocol/inspector/issues/495/
	// https://github.com/modelcontextprotocol/inspector/blob/0.14.0/cli/src/cli.ts#L70-L71

	if (process.env.CLIENT_PORT === undefined) {
		process.env.CLIENT_PORT = "6274"
	}

	if (process.env.SERVER_PORT === undefined) {
		process.env.SERVER_PORT = "6277"
	}
}

export function environ(): string[] {
	let environ: string[] = []

	for (let [k, v] of Object.entries(process.env)) {
		if (v !== undefined && envs.has(k)) {
			environ.push(`${k}=${v}`)
		}
	}

	return environ
}
