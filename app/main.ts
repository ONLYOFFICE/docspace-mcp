#!/usr/bin/env node

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

import {Server as ProtocolServer} from "@modelcontextprotocol/sdk/server/index.js"
import {StdioServerTransport} from "@modelcontextprotocol/sdk/server/stdio.js"
import type {SafeParseReturnType} from "zod"
import type {Config as ClientConfig} from "../lib/client.ts"
import {Client} from "../lib/client.ts"
import {Resolver} from "../lib/resolver.ts"
import type {Config as ServerConfig} from "../lib/server.ts"
import {ConfiguredServer, MisconfiguredServer} from "../lib/server.ts"
import {Uploader} from "../lib/uploader.ts"
import pack from "../package.json" with {type: "json"}
import type {Config as AppConfig} from "./config.ts"
import {ConfigSchema} from "./config.ts"

async function main(): Promise<void> {
	let c = ConfigSchema.safeParse(process.env)
	let s = createServer(c)
	let t = new StdioServerTransport()
	await s.connect(t)
}

function createServer(config: SafeParseReturnType<unknown, AppConfig>): ProtocolServer {
	let ps = new ProtocolServer(
		{
			name: pack.name,
			version: pack.version,
		},
		{
			capabilities: {
				tools: {},
				logging: {},
			},
		},
	)

	if (config.success) {
		let lc = createClient(config.data)

		let lr = new Resolver(lc.files.getOperationStatuses.bind(lc.files))
		let lu = new Uploader(lc)

		let sc: ServerConfig = {
			server: ps,
			client: lc,
			resolver: lr,
			uploader: lu,
			dynamic: config.data.dynamic,
			toolsets: config.data.toolsets,
		}

		let _ = new ConfiguredServer(sc)
	} else {
		let _ = new MisconfiguredServer(ps, config.error)
	}

	return ps
}

function createClient(config: AppConfig): Client {
	let f: ClientConfig = {
		baseUrl: config.baseUrl,
		userAgent: config.userAgent,
		fetch,
	}

	if (config.origin) {
		f.fetch = withOrigin(f.fetch, config.origin)
	}

	let c = new Client(f)

	if (config.apiKey) {
		c = c.withApiKey(config.apiKey)
	}

	if (config.authToken) {
		c = c.withAuthToken(config.authToken)
	}

	if (config.username && config.password) {
		c = c.withBasicAuth(config.username, config.password)
	}

	return c
}

function withOrigin(f: typeof fetch, o: string): typeof fetch {
	return async function fetch(input, init) {
		if (!(input instanceof Request)) {
			throw new Error("Unsupported input type.")
		}

		input = input.clone()
		input.headers.set("Origin", o)

		return await f(input, init)
	}
}

await main()
