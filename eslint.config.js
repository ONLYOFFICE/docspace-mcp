import config from "@vanyauhalin/eslint-config"

export default [
	...config,
	{
		files: ["**/*.json"],
		rules: {
			"jsonc/array-bracket-newline": ["error", {minItems: 1}],
			"jsonc/object-curly-newline": ["error", {minProperties: 1}],
		},
	},
	{
		files: ["**/*.ts"],
		rules: {
			"es-x/no-object-getownpropertysymbols": "off",
			"import-x/no-deprecated": "off",
			"stylistic/space-before-function-paren": ["error", {anonymous: "never", asyncArrow: "never", catch: "always", named: "never"}],
			"typescript/no-deprecated": ["error", {allow: [{from: "package", package: "@modelcontextprotocol/sdk", name: "Server"}, {from: "package", package: "@modelcontextprotocol/sdk", name: "SSEClientTransport"}, {from: "package", package: "@modelcontextprotocol/sdk", name: "SSEServerTransport"}]}],
		},
	},
]
