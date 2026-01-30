import config from "@vanyauhalin/eslint-config"

export default [
	...config,
	{
		files: ["app/main.ts"],
		rules: {
			"n/hashbang": "off",
			"unicorn/prefer-top-level-await": "off",
		},
	},
	{
		files: ["**/*.ts"],
		rules: {
			"es-x/no-export-ns-from": "off",
			"jsdoc/check-tag-names": ["error", {definedTags: ["mergeModuleWith"]}],
			"new-cap": ["error", {capIsNew: false}],
			"typescript/no-deprecated": ["error", {allow: [{from: "package", package: "@modelcontextprotocol/sdk", name: "Server"}, {from: "package", package: "@modelcontextprotocol/sdk", name: "SSEClientTransport"}, {from: "package", package: "@modelcontextprotocol/sdk", name: "SSEServerTransport"}]}],
			"unicorn/import-style": "off",
			"unicorn/prefer-add-event-listener": "off",
		},
	},
]
