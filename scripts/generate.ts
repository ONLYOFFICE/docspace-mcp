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
import {readFile, writeFile} from "node:fs/promises"
import type {ListToolsResult} from "@modelcontextprotocol/sdk/types.js"
import {RawConfigSchema} from "../app/config.ts"
import type {Config as ServerConfig} from "../lib/server.ts"
import {Server} from "../lib/server.ts"

/**
 * {@link https://code.visualstudio.com/docs/reference/variables-reference/#_input-variables | VS Code Reference}
 */
interface VscodeInput {
	type: string
	id: string
	description: string
	password?: boolean
}

/**
 * {@link https://code.visualstudio.com/docs/copilot/chat/mcp-servers/#_configuration-format | VS Code Reference}
 */
interface VscodeConfig {
	env: Record<string, string>
	command: string
	args: string[]
}

interface VscodeQuery {
	name: string
	inputs: string
	config: string
	quality?: string
}

async function main(): Promise<void> {
	if (!existsSync("README.md")) {
		throw new Error("README.md not found")
	}

	let input = await readFile("README.md", "utf8")

	let c: ServerConfig = {
		// @ts-ignore
		server: {
			setRequestHandler() {},
		},
	}

	let s = new Server(c)

	let ls = s.listTools().tools.sort((a, b) => {
		return a.name.localeCompare(b.name)
	})

	let badges = createBadges(RawConfigSchema.shape)
	let config = formatConfig(RawConfigSchema.shape)
	let tools = formatTools(ls)

	let output = input
	output = insert("badges", output, badges)
	output = insert("config", output, config)
	output = insert("tools", output, tools)

	await writeFile("README.md", output, "utf8")
}

function createBadges(shape: typeof RawConfigSchema.shape): string {
	let bru = "https://badgen.net/static/Open%20in%20VS%20Code/npx/blue"
	let biu = "https://badgen.net/static/Open%20in%20VS%20Code%20Insiders/npx/cyan"

	let inputs: VscodeInput[] = [
		{
			type: "promptString",
			id: "docspace_base_url",
			description: String(shape.DOCSPACE_BASE_URL.description).replaceAll("`", ""),
		},
		{
			type: "promptString",
			id: "docspace_api_key",
			description: String(shape.DOCSPACE_API_KEY.description).replaceAll("`", ""),
			password: true,
		},
	]

	let config: VscodeConfig = {
		env: {
			DOCSPACE_BASE_URL: "${input:docspace_base_url}",
			DOCSPACE_API_KEY: "${input:docspace_api_key}",
		},
		command: "npx",
		args: ["--yes", "@onlyoffice/docspace-mcp"],
	}

	let query: VscodeQuery = {
		name: "onlyoffice-docspace",
		inputs: JSON.stringify(inputs),
		config: JSON.stringify(config),
	}

	let vbu = "https://insiders.vscode.dev/redirect/mcp/install"

	let vru = new URL(vbu)
	vru.search = new URLSearchParams({...query}).toString()

	query.quality = "insiders"

	let viu = new URL(vbu)
	viu.search = new URLSearchParams({...query}).toString()

	let c = ""

	c += `[![Open in VS Code using npx command](${bru})](${vru})\n`
	c += `[![Open in VS Code Insiders using npx command](${biu})](${viu})`

	return c
}

function formatConfig(shape: typeof RawConfigSchema.shape): string {
	let c = "| Name | Description |\n|-|-|\n"

	for (let [k, v] of Object.entries(shape)) {
		c += `| \`${k}\` | ${v.description} |\n`
	}

	if (c.length !== 0) {
		c = c.slice(0, -1)
	}

	return c
}

function formatTools(tools: ListToolsResult["tools"]): string {
	let c = "| # | Name | Description |\n|-|-|-|\n"

	for (let [i, t] of tools.entries()) {
		c += `| ${i + 1} | \`${t.name}\` | ${t.description} |\n`
	}

	if (c.length !== 0) {
		c = c.slice(0, -1)
	}

	return c
}

function insert(section: string, content: string, patch: string): string {
	let b: string[] = []

	let inside = false
	let found = false

	for (let l of content.split("\n")) {
		if (l === `<!--generate ${section}-start-->`) {
			inside = true
			found = true
			b.push(l)
			b.push("")
			b.push(patch)
			b.push("")
			continue
		}

		if (l === `<!--generate ${section}-end-->` && inside) {
			inside = false
			b.push(l)
			continue
		}

		if (!inside) {
			b.push(l)
			continue
		}
	}

	if (!found) {
		throw new Error(`Section ${section} not found`)
	}

	return b.join("\n")
}

await main()
