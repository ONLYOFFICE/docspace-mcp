import child from "node:child_process"
import fs from "node:fs/promises"
import path from "node:path"
import util from "node:util"
import ajv from "ajv"
import ajvFormats from "ajv-formats"
import * as mcp from "../lib/mcp.ts"
import * as meta from "../lib/meta.ts"
import * as config from "./config.ts"
import * as tools from "./tools.ts"

// eslint-disable-next-line typescript/strict-void-return
const exec = util.promisify(child.exec)

type Manifest = {
	$schema?: string
	version?: string
	documentation?: string
	server?: Server
	tools?: Tool[]
	user_config?: Record<string, Option>
}

type Server = {
	mcp_config?: McpConfig
}

type McpConfig = {
	env?: Record<string, string>
}

type Tool = {
	name?: string
	description?: string
}

type Option = {
	type?: string
	title?: string
	description?: string
	required?: boolean
	default?: unknown
}

const files: string[] = [
	"bin/onlyoffice-docspace-mcp.js",
	"docs/icon.png",
	"LICENSE",
	"README.md",
]

async function main(): Promise<void> {
	let aa = new ajv.Ajv()
	ajvFormats.default(aa)

	let mc = await fs.readFile("manifest.template.json", "utf8")
	let mo = JSON.parse(mc) as Manifest

	if (!mo.$schema) {
		throw new Error("Manifest schema is not defined")
	}

	if (!mo.documentation) {
		throw new Error("Manifest documentation is not defined")
	}

	if (!mo.server) {
		throw new Error("Manifest server is not defined")
	}

	if (!mo.server.mcp_config) {
		throw new Error("Manifest server.mcp_config is not defined")
	}

	if (!mo.server.mcp_config.env) {
		throw new Error("Manifest server.mcp_config.env is not defined")
	}

	if (!mo.tools) {
		throw new Error("Manifest tools is not defined")
	}

	if (!mo.user_config) {
		throw new Error("Manifest user_config is not defined")
	}

	let sc = await fs.readFile(mo.$schema, "utf8")
	let so = JSON.parse(sc) as ajv.AnySchema

	let av = aa.compile(so)

	mo.version = meta.version
	mo.documentation = mo.documentation.replace("{{version}}", meta.version)

	for (let o of config.options) {
		if (o.transports.includes("stdio") && o.distribution.includes("mcpb")) {
			let k = o.env.replace("DOCSPACE_", "").toLowerCase()
			mo.server.mcp_config.env[o.env] = `\${user_config.${k}}`
			mo.user_config[k] = {
				type: o.type,
				title: o.title,
				description: o.description,
				required: false,
				default: o.default,
			}
		}
	}

	for (let s of tools.sortToolsets(mcp.toolsetInfos)) {
		for (let t of s.tools) {
			let o: Tool = {
				name: t.name,
				description: t.description,
			}
			mo.tools.push(o)
		}
	}

	if (!av(mo)) {
		throw new Error("Validating manifest", {cause: av.errors})
	}

	mc = JSON.stringify(mo, null, 2)

	await fs.rm("tmp", {recursive: true, force: true})

	for (let f of files) {
		let t = path.join("tmp", f)
		let d = path.dirname(t)
		await fs.mkdir(d, {recursive: true})
		await fs.copyFile(f, t)
	}

	await fs.writeFile("tmp/manifest.json", mc)

	await exec(
		`pnpm exec mcpb pack tmp onlyoffice-docspace-mcp-${meta.version}.mcpb`,
		{env: process.env},
	)

	await fs.rm("tmp", {recursive: true, force: true})
}

await main()
