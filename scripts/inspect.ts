import child from "node:child_process"
import * as env from "./env.ts"

function main(): void {
	env.load()

	let args: string[] = ["exec", "mcp-inspector"]

	for (let e of env.environ()) {
		args.push("-e", e)
	}

	args.push("--", "node", "app/main.ts")

	child.spawn("pnpm", args, {
		env: process.env,
		stdio: "inherit",
		shell: true,
	})
}

main()
