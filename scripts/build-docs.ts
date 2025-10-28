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

/* eslint-disable typescript/consistent-type-definitions */

import * as fs from "node:fs/promises"
import * as mcp from "../lib/mcp.ts"
import type * as utilMcp from "../lib/util/mcp.ts"
import * as tools from "./tools.ts"

/**
 * {@link https://docs.cursor.com/en/tools/developers#mcp-servers | Cursor Reference}
 */
type CursorQuery = {
	name: string
	config: string
}

type VscodeQuery = {
	name: string
	inputs: string
	config: string
	quality?: string
}

/**
 * {@link https://code.visualstudio.com/docs/reference/variables-reference/#_input-variables | VS Code Reference}
 */
type VscodeInput = {
	type: string
	id: string
	description: string
	password?: boolean
}

/**
 * {@link https://code.visualstudio.com/docs/copilot/chat/mcp-servers/#_configuration-format | VS Code Reference}
 */
type Config = {
	command: string
	args: string[]
	env: ConfigEnv
}

type ConfigEnv = {
	DOCSPACE_BASE_URL: string
	DOCSPACE_API_KEY: string
}

async function main(): Promise<void> {
	await Promise.all([
		updateTools("docs/features/tools.md"),
		updateQuickInstall("docs/installation/local-server.md"),
	])
}

async function updateTools(f: string): Promise<void> {
	let s = await fs.readFile(f, "utf8")

	let toolsets = tools.sortToolsets(mcp.toolsetInfos)
	let metaTools = tools.sortTools(mcp.metaToolInfos)

	let o = createToolsetsTable(toolsets)
	s = insert("toolsets", s, o)

	let m = createMetaToolsTable(metaTools)
	s = insert("meta-tools", s, m)

	let t = createToolsTable(toolsets)
	s = insert("tools", s, t)

	await fs.writeFile(f, s, "utf8")
}

async function updateQuickInstall(f: string): Promise<void> {
	let s = await fs.readFile(f, "utf8")

	let t = createQuickInstallTable()
	s = insert("quick-install", s, t)

	await fs.writeFile(f, s, "utf8")
}

function createQuickInstallTable(): string {
	let c = ""
	let b = ""
	let i = ""
	let x = ""
	let y = ""

	i = createBadgenLink("Cursor", "black")
	x = createCursorDockerImageLink()
	x = createMarkdownBadge("Add to Cursor using Docker Image", i, x)
	y = createCursorNpxLink()
	y = createMarkdownBadge("Add to Cursor using npx", i, y)
	b += `| ${x} | ${y} |\n`

	i = createBadgenLink("VS Code", "blue")
	x = createVscodeDockerImageLink()
	x = createMarkdownBadge("Add to VS Code using Docker Image", i, x)
	y = createVscodeNpxLink()
	y = createMarkdownBadge("Add to VS Code using npx", i, y)
	b += `| ${x} | ${y} |\n`

	i = createBadgenLink("VS Code Insiders", "cyan")
	x = createVscodeInsidersDockerImageLink()
	x = createMarkdownBadge("Add to VS Code Insiders using Docker Image", i, x)
	y = createVscodeInsidersNpxLink()
	y = createMarkdownBadge("Add to VS Code Insiders using npx", i, y)
	b += `| ${x} | ${y} |\n`

	b = b.slice(0, -1)

	let h = "| Docker Image | Node.js Application |\n|:-:|:-:|"
	c = `${h}\n${b}`

	return c
}

function createBadgenLink(n: string, c: string): string {
	let s = `https://badgen.net/static/Add to/${n}/${c}`
	let u = new URL(s)
	return u.toString()
}

function createMarkdownBadge(l: string, i: string, a: string): string {
	return `[![${l}](${i})](${a})`
}

function createCursorDockerImageLink(): string {
	let e = createSharedConfigEnv()
	let c = createDockerImageConfig(e)
	let q = createCursorQuery(c)
	let u = createCursorLink(q)
	return u
}

function createCursorNpxLink(): string {
	let e = createSharedConfigEnv()
	let c = createNpxConfig(e)
	let q = createCursorQuery(c)
	let u = createCursorLink(q)
	return u
}

function createCursorQuery(c: Config): CursorQuery {
	return {
		name: "onlyoffice-docspace",
		config: Buffer.from(JSON.stringify(c)).toString("base64"),
	}
}

function createCursorLink(q: CursorQuery): string {
	let s = "https://cursor.com/en/install-mcp"
	let u = new URL(s)
	let p = new URLSearchParams(q)
	u.search = p.toString()
	return u.toString()
}

function createVscodeDockerImageLink(): string {
	let i = createVscodeInputs()
	let e = createVscodeConfigEnv()
	let c = createDockerImageConfig(e)
	let q = createVscodeQuery(i, c)
	let u = createVscodeLink(q)
	return u
}

function createVscodeNpxLink(): string {
	let i = createVscodeInputs()
	let e = createSharedConfigEnv()
	let c = createNpxConfig(e)
	let q = createVscodeQuery(i, c)
	let u = createVscodeLink(q)
	return u
}

function createVscodeInsidersDockerImageLink(): string {
	let i = createVscodeInputs()
	let e = createVscodeConfigEnv()
	let c = createDockerImageConfig(e)
	let q = createVscodeInsidersQuery(i, c)
	let u = createVscodeLink(q)
	return u
}

function createVscodeInsidersNpxLink(): string {
	let i = createVscodeInputs()
	let e = createSharedConfigEnv()
	let c = createNpxConfig(e)
	let q = createVscodeInsidersQuery(i, c)
	let u = createVscodeLink(q)
	return u
}

function createVscodeInputs(): VscodeInput[] {
	return [
		{
			type: "promptString",
			id: "docspace_base_url",
			description: "The base URL of the DocSpace instance for API requests.",
		},
		{
			type: "promptString",
			id: "docspace_api_key",
			description: "The API key for accessing the DocSpace API.",
			password: true,
		},
	]
}

function createVscodeConfigEnv(): ConfigEnv {
	return {
		DOCSPACE_BASE_URL: "${input:docspace_base_url}",
		DOCSPACE_API_KEY: "${input:docspace_api_key}",
	}
}

function createVscodeInsidersQuery(i: VscodeInput[], c: Config): VscodeQuery {
	let q = createVscodeQuery(i, c)
	q.quality = "insiders"
	return q
}

function createVscodeQuery(i: VscodeInput[], c: Config): VscodeQuery {
	return {
		name: "onlyoffice-docspace",
		inputs: JSON.stringify(i),
		config: JSON.stringify(c),
	}
}

function createVscodeLink(q: VscodeQuery): string {
	let s = "https://insiders.vscode.dev/redirect/mcp/install"
	let u = new URL(s)
	let p = new URLSearchParams(q)
	u.search = p.toString()
	return u.toString()
}

function createSharedConfigEnv(): ConfigEnv {
	return {
		DOCSPACE_BASE_URL: "https://your-instance.onlyoffice.com",
		DOCSPACE_API_KEY: "your-api-key",
	}
}

function createDockerImageConfig(e: ConfigEnv): Config {
	return {
		command: "docker",
		args: [
			"run",
			"--interactive",
			"--rm",
			"--env",
			"DOCSPACE_BASE_URL",
			"--env",
			"DOCSPACE_API_KEY",
			"onlyoffice/docspace-mcp",
		],
		env: e,
	}
}

function createNpxConfig(e: ConfigEnv): Config {
	return {
		command: "npx",
		args: ["--yes", "@onlyoffice/docspace-mcp"],
		env: e,
	}
}

function createToolsetsTable(toolsets: utilMcp.ToolsetInfo[]): string {
	let c = ""

	for (let [i, t] of toolsets.entries()) {
		c += `| ${i + 1} | \`${t.name}\` | ${t.description} |\n`
	}

	if (c.length !== 0) {
		c = c.slice(0, -1)

		let h = "| # | Toolset Name | Toolset Description |\n|-|-|-|"

		c = `${h}\n${c}`
	}

	if (c.length === 0) {
		throw new Error("Toolsets table is empty")
	}

	return c
}

function createToolsTable(toolsets: utilMcp.ToolsetInfo[]): string {
	let c = ""

	let i = 0

	for (let s of toolsets) {
		let b = ""

		for (let [j, t] of s.tools.entries()) {
			// eslint-disable-next-line github/unescaped-html-literal
			b += `<tr><td>${j + 1 + i}</td><td><code>${t.name}</code></td><td>${t.description}</td></tr>\n`
		}

		if (b.length !== 0) {
			b = b.slice(0, -1)

			let n = s.name[0].toUpperCase() + s.name.slice(1)

			// eslint-disable-next-line github/unescaped-html-literal
			let h = `<tr><td></td><th scope="rowgroup">${n} Toolset</th><td></td></tr>`

			// eslint-disable-next-line github/unescaped-html-literal
			b = `<tbody>\n${h}\n${b}\n</tbody>`

			c += `${b}\n`
		}

		i += s.tools.length
	}

	if (c.length !== 0) {
		c = c.slice(0, -1)

		// eslint-disable-next-line github/unescaped-html-literal
		let h = "<thead>\n<tr><th>#</th><th>Tool Name</th><th>Tool Description</th></tr>\n</thead>"

		// eslint-disable-next-line github/unescaped-html-literal
		c = `<table>\n${h}\n${c}\n</table>`
	}

	if (c.length === 0) {
		throw new Error("Tools table is empty")
	}

	return c
}

function createMetaToolsTable(tools: utilMcp.Summary[]): string {
	let c = ""

	for (let [i, t] of tools.entries()) {
		c += `| ${i + 1} | \`${t.name}\` | ${t.description} |\n`
	}

	if (c.length !== 0) {
		c = c.slice(0, -1)

		let h = "| # | Meta Tool Name | Meta Tool Description |\n|-|-|-|"

		c = `${h}\n${c}`
	}

	if (c.length === 0) {
		throw new Error("Meta tools table is empty")
	}

	return c
}

function insert(s: string, c: string, p: string): string {
	let b: string[] = []

	let inside = false
	let found = false

	for (let l of c.split("\n")) {
		if (l === `<!--generate ${s}-start-->`) {
			inside = true
			found = true
			b.push(l)
			b.push("")
			b.push(p)
			b.push("")
			continue
		}

		if (l === `<!--generate ${s}-end-->` && inside) {
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
		throw new Error(`Section ${s} not found`)
	}

	return b.join("\n")
}

await main()
