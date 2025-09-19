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

import crypto from "node:crypto"
import fs from "node:fs/promises"
import ajv from "ajv"
import ajvFormats from "ajv-formats"
import * as meta from "../lib/meta.ts"
import * as config from "./config.ts"

interface Detail {
	$schema?: string
	version?: string
	website_url?: string
	packages?: Package[]
}

interface Package {
	registry_type?: string
	identifier?: string
	version?: string
	file_sha256?: string
	transport?: Transport
	environment_variables?: Value[]
}

interface Transport {
	type?: string
	url?: string
	headers?: Value[]
}

interface Value {
	description?: string
	is_required?: boolean
	format?: "string" | "number" | "boolean"
	is_secret?: boolean
	default?: string
	choices?: string[]
	name?: string
}

async function main(): Promise<void> {
	let aa = new ajv.Ajv()
	aa.addKeyword("example")
	ajvFormats.default(aa)

	let mc = await fs.readFile("server.template.json", "utf8")
	let mo = JSON.parse(mc) as Detail

	if (!mo.$schema) {
		throw new Error("Manifest schema is not defined")
	}

	if (!mo.website_url) {
		throw new Error("Manifest website_url is not defined")
	}

	if (!mo.packages) {
		throw new Error("Manifest packages is not defined")
	}

	let sc = await fetch(mo.$schema)
	let so = await sc.json() as ajv.AnySchema

	let av = aa.compile(so)

	mo.version = meta.version
	mo.website_url = mo.website_url.replace("{{version}}", meta.version)

	let envs: Record<config.Distribution, Record<config.Transport, Value[]>> = {
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

	let headers: Value[] = []

	for (let o of config.options) {
		let v: Value = {
			description: o.description,
			is_required: false,
			format: o.type,
			is_secret: o.sensitive,
			default: o.default.toString(),
			choices: o.choices,
			name: o.env,
		}

		for (let d of o.distribution) {
			for (let t of o.transports) {
				envs[d][t].push(v)
			}
		}

		if (o.header) {
			v = {...v}

			v.name = o.header

			headers.push(v)
		}
	}

	let packages: Package[] = []

	for (let p of mo.packages) {
		if (!p.registry_type) {
			throw new Error("Package registry_type is not defined")
		}

		if (!p.identifier) {
			throw new Error("Package identifier is not defined")
		}

		switch (p.registry_type) {
		case "mcpb":
			let a = await fs.readFile("onlyoffice-docspace-mcp-2.0.0.mcpb")

			p.identifier = p.identifier.replaceAll("{{version}}", meta.version)
			p.version = meta.version
			p.file_sha256 = crypto.createHash("sha256").update(a).digest("hex")

			p.transport = {
				type: "stdio",
			}

			p.environment_variables = envs.mcpb.stdio

			packages.push(p)

			break

		case "npm":
			p.version = meta.version

			p.transport = {
				type: "stdio",
			}

			p.environment_variables = envs.js.stdio

			packages.push(p)

			p = {...p}

			p.transport = {
				type: "sse",
				url: "https://example.com/sse",
				headers,
			}

			p.environment_variables = envs.js.sse

			packages.push(p)

			p = {...p}

			p.transport = {
				type: "streamable-http",
				url: "https://example.com/mcp",
				headers,
			}

			p.environment_variables = envs.js["streamable-http"]

			packages.push(p)

			break

		case "oci":
			p.version = meta.version

			p.transport = {
				type: "stdio",
			}

			p.environment_variables = envs.oci.stdio

			packages.push(p)

			p = {...p}

			p.transport = {
				type: "sse",
				url: "https://example.com/mcp",
				headers,
			}

			p.environment_variables = envs.oci.sse

			packages.push(p)

			p = {...p}

			p.transport = {
				type: "streamable-http",
				url: "https://example.com/mcp",
				headers,
			}

			p.environment_variables = envs.oci["streamable-http"]

			packages.push(p)

			break
		}
	}

	mo.packages = packages

	if (!av(mo)) {
		throw new Error("Validating manifest", {cause: av.errors})
	}

	mc = JSON.stringify(mo, null, 2)

	await fs.writeFile("server.json", mc)
}

await main()
