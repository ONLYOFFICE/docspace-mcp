import child from "node:child_process"
import * as env from "./env.ts"

function main(): void {
	env.load()

	let args: string[] = []

	if (process.env.HTTP_PROXY !== undefined) {
		args.push("--require", "./scripts/proxy.ts")
	}

	args.push("app/main.ts")

	child.spawn("node", args, {
		env: process.env,
		stdio: "inherit",
		shell: true,
	})
}

main()
