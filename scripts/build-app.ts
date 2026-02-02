import esbuild from "esbuild"

async function main(): Promise<void> {
	await esbuild.build({
		banner: {
			js: `import __module from "node:module";
var require = __module.createRequire(import.meta.url);
`,
		},
		bundle: true,
		entryPoints: ["app/main.ts"],
		format: "esm",
		logLevel: "error",
		outfile: "bin/onlyoffice-docspace-mcp.js",
		platform: "node",
		target: "es2015",
	})
}

await main()
