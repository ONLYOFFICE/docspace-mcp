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

import * as child from "node:child_process"
import * as env from "./env.ts"

function main(): void {
	env.load()

	let args: string[] = ["exec", "mcp-inspector"]

	for (let e of env.environ()) {
		args.push("-e", e)
	}

	args.push("--", "node")

	if (process.env.HTTP_PROXY !== undefined) {
		args.push("--require", "./scripts/proxy.ts")
	}

	args.push("app/main.ts")

	child.spawn("pnpm", args, {
		env: process.env,
		stdio: "inherit",
		shell: true,
	})
}

main()
