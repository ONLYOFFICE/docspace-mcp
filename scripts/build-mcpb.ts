import child from "node:child_process"
import fs from "node:fs/promises"
import path from "node:path"
import util from "node:util"
import * as spec from "../lib/config/spec.ts"
import * as config from "../lib/config.ts"
import type * as dist from "../lib/dist.ts"
import * as mcp from "../lib/mcp.ts"
import * as meta from "../lib/meta.ts"
import * as tools from "./tools.ts"

// eslint-disable-next-line typescript/strict-void-return
const exec = util.promisify(child.exec)

const files: string[] = [
	"bin/onlyoffice-docspace-mcp.js",
	"docs/icon.png",
	"LICENSE",
	"README.md",
]

async function main(): Promise<void> {
	let mc = await fs.readFile("manifest.template.json", "utf8")

	let mo = JSON.parse(mc) as dist.Manifest

	mo.version = meta.version
	mo.documentation = mo.documentation.replace("{{version}}", meta.version)

	for (let o of Object.values(spec)) {
		if (o.distributions.includes("mcpb")) {
			let k = `${config.envPrefix}${o.env}`.toLowerCase()
			mo.server.mcp_config.env[`${config.envPrefix}${o.env}`] = `\${user_config.${k}}`
			mo.user_config[k] = {
				type: o.type,
				title: o.title,
				description: o.description,
				required: false,
				default: o.default,
			}
		}
	}

	for (let s of tools.sortToolsets(mcp.regularToolsets)) {
		for (let t of s.tools) {
			let o: dist.ManifestTool = {
				name: t.name,
				description: t.description,
			}
			mo.tools.push(o)
		}
	}

	mc = JSON.stringify(mo, null, 2)

	for (let f of files) {
		let t = path.join("./mcpb/", f)
		let d = path.dirname(t)
		await fs.mkdir(d, {recursive: true})
		await fs.copyFile(f, t)
	}

	await fs.writeFile("./mcpb/manifest.json", mc)

	await exec(
		`pnpm exec mcpb pack ./mcpb/ ./onlyoffice-docspace-mcp-${meta.version}.mcpb`,
		{env: process.env},
	)
}

await main()
