import child from "node:child_process"
import * as env from "./env.ts"

function main(): void {
	env.load()

	child.spawn("node", ["app/main.ts"], {
		env: process.env,
		stdio: "inherit",
		shell: true,
	})
}

main()
