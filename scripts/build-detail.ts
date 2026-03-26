import crypto from "node:crypto"
import fs from "node:fs/promises"
import * as spec from "../lib/config/spec.ts"
import * as config from "../lib/config.ts"
import type * as dist from "../lib/dist.ts"
import * as meta from "../lib/meta.ts"

async function main(): Promise<void> {
	let mc = await fs.readFile("./server.template.json", "utf8")

	let mo = JSON.parse(mc) as dist.Detail

	mo.version = meta.version

	let envs: Record<spec.ItemDistribution, Record<spec.ItemTransport, dist.DetailValue[]>> = {
		js: {
			"stdio": [],
			"sse": [],
			"streamable-http": [],
		},
		mcpb: {
			"stdio": [],
			"sse": [],
			"streamable-http": [],
		},
		oci: {
			"stdio": [],
			"sse": [],
			"streamable-http": [],
		},
	}

	let headers: dist.DetailValue[] = []

	for (let o of Object.values(spec)) {
		let v: dist.DetailValue = {
			description: o.description,
			isRequired: false,
			format: o.type,
			isSecret: o.sensitive,
			default: o.default.toString(),
			choices: o.choices,
			name: `${config.envPrefix}${o.env}`,
		}

		for (let d of o.distributions) {
			for (let t of o.transports) {
				envs[d][t].push(v)
			}
		}

		if (o.header) {
			v = {...v}

			v.name = `${spec.requestHeaderPrefix.default}${o.header}`

			headers.push(v)
		}
	}

	let packages: dist.DetailPackage[] = []

	for (let p of mo.packages) {
		if (!p.registryType) {
			throw new Error("Package registry_type is not defined")
		}

		if (!p.identifier) {
			throw new Error("Package identifier is not defined")
		}

		switch (p.registryType) {
		case "mcpb":
			let a = await fs.readFile(`./onlyoffice-docspace-mcp-${meta.version}.mcpb`)

			p.identifier = p.identifier.replaceAll("{{version}}", meta.version)
			p.version = meta.version
			p.fileSha256 = crypto.createHash("sha256").update(a).digest("hex")

			p.transport = {
				type: "stdio",
			}

			p.environmentVariables = envs.mcpb.stdio

			packages.push(p)

			break

		case "npm":
			p.version = meta.version

			p.transport = {
				type: "stdio",
			}

			p.environmentVariables = envs.js.stdio

			packages.push(p)

			p = {...p}

			p.transport = {
				type: "sse",
				url: "https://example.com/sse",
				headers,
			}

			p.environmentVariables = envs.js.sse

			packages.push(p)

			p = {...p}

			p.transport = {
				type: "streamable-http",
				url: "https://example.com/mcp",
				headers,
			}

			p.environmentVariables = envs.js["streamable-http"]

			packages.push(p)

			break

		case "oci":
			p.identifier = p.identifier.replaceAll("{{version}}", meta.version)

			p.transport = {
				type: "stdio",
			}

			p.environmentVariables = envs.oci.stdio

			packages.push(p)

			p = {...p}

			p.transport = {
				type: "sse",
				url: "https://example.com/mcp",
				headers,
			}

			p.environmentVariables = envs.oci.sse

			packages.push(p)

			p = {...p}

			p.transport = {
				type: "streamable-http",
				url: "https://example.com/mcp",
				headers,
			}

			p.environmentVariables = envs.oci["streamable-http"]

			packages.push(p)

			break
		}
	}

	mo.packages = packages

	mo.remotes = [
		{
			type: "sse",
			url: "https://mcp.onlyoffice.com/sse",
			headers,
		},
		{
			type: "streamable-http",
			url: "https://mcp.onlyoffice.com/mcp",
			headers,
		},
	]

	mc = JSON.stringify(mo, null, 2)

	await fs.writeFile("./server.json", mc)
}

await main()
