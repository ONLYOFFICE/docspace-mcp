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

import * as logger from "../lib/util/logger.ts"
import * as config from "./config.ts"
import * as http from "./http.ts"
import type * as shared from "./shared.ts"
import * as stdio from "./stdio.ts"

const SIGNALS = ["SIGTERM", "SIGINT"]

async function main(): Promise<void> {
	let l: logger.VanillaLogger | undefined

	try {
		let c = config.global.load()

		l = new logger.VanillaLogger(process.stdout)

		if (c.err || c.v.mcp.transport === "stdio") {
			l.mute()
		}

		if (c.err) {
			l.error("Loading config", {err: c.err})
		} else {
			l.info("Loaded config", config.global.format(c.v))
		}

		if (c.err) {
			let [p, cleanup] = stdio.misconfigured.start(c.err)
			watch(l, cleanup)
			await start(l, p, cleanup)
			return
		}

		config.request.setup(c.v)

		if (c.v.mcp.transport === "stdio") {
			let [p, cleanup] = stdio.configured.start(c.v)
			watch(l, cleanup)
			await start(l, p, cleanup)
		} else {
			let [p, cleanup] = http.start(c.v, l)
			watch(l, cleanup)
			await start(l, p, cleanup)
		}
	} catch (err) {
		if (l) {
			l.error("Executing main", {err})
		}
		process.exit(1)
	}
}

async function start(
	l: logger.VanillaLogger,
	p: shared.P,
	cleanup: shared.Cleanup,
): Promise<void> {
	let err = await p
	if (err) {
		l.error("Server failed to start", {err})

		err = await cleanup()
		if (err) {
			l.error("Cleaning up", {err})
		}

		process.exit(1)
	}
}

function watch(l: logger.VanillaLogger, cleanup: shared.Cleanup): void {
	for (let s of SIGNALS) {
		process.on(s, () => {
			void (async() => {
				l.info(`Received ${s}, shutting down`)

				let err = await cleanup()
				if (err) {
					l.error("Cleaning up", {err})
				}

				if (err) {
					l.error("Shut down with an error", {err})
					process.exit(1)
				}

				l.info("Shut down successfully")
				process.exit(0)
			})()
		})
	}
}

void main()
