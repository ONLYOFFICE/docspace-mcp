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

import child from "node:child_process"
import util from "node:util"
import * as env from "./env.ts"

const exec = util.promisify(child.exec)

async function main(): Promise<void> {
	env.load()

	let args: string[] = ["run", "-it"]

	args.push("--entrypoint", "/bin/sh")
	args.push("-e", `CLIENT_PORT=${process.env.CLIENT_PORT}`)
	args.push("-e", `SERVER_PORT=${process.env.SERVER_PORT}`)
	args.push("-w", "/srv/onlyoffice-docspace-mcp")
	args.push("-p", `${process.env.CLIENT_PORT}:${process.env.CLIENT_PORT}`)
	args.push("-p", `${process.env.SERVER_PORT}:${process.env.SERVER_PORT}`)
	args.push("-v", "./:/srv/onlyoffice-docspace-mcp")
	args.push("-v", "/srv/onlyoffice-docspace-mcp/.pnpm-store")
	args.push("-v", "/srv/onlyoffice-docspace-mcp/node_modules")

	let version: string | undefined

	try {
		let p = await exec("mise version --json", {env: process.env})
		let j = JSON.parse(p.stdout)
		version = j.version.split(" ")[0]
	} catch {
		version = "latest"
	}

	args.push(`jdxcode/mise:${version}`)

	child.spawn("docker", args, {
		env: process.env,
		stdio: "inherit",
		shell: true,
	})
}

await main()
