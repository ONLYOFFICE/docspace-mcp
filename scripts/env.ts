import * as fs from "node:fs"
import * as config from "../lib/config.ts"

const envs: string[] = [
	"HTTP_PROXY",
]

export function load(): void {
	if (fs.existsSync(".env")) {
		process.loadEnvFile(".env")
	}

	// https://github.com/modelcontextprotocol/inspector/issues/495/
	// https://github.com/modelcontextprotocol/inspector/blob/0.14.0/cli/src/cli.ts#L70-L71

	if (process.env.CLIENT_PORT === undefined) {
		process.env.CLIENT_PORT = "6274"
	}

	if (process.env.SERVER_PORT === undefined) {
		process.env.SERVER_PORT = "6277"
	}
}

export function environ(): string[] {
	let environ: string[] = []

	for (let [k, v] of Object.entries(process.env)) {
		if (v !== undefined && (envs.includes(k) || k.startsWith(config.envPrefix))) {
			environ.push(`${k}=${v}`)
		}
	}

	return environ
}
