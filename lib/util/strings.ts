/**
 * @module util/strings
 */

export function escapeWhitespace(s: string): string {
	return s.replaceAll("\n", String.raw`\n`).replaceAll("\t", String.raw`\t`)
}

export function camelCaseToSnakeCase(s: string): string {
	return s.replaceAll(/(?<=[a-z])(?=[A-Z])/g, "_").toLowerCase()
}
