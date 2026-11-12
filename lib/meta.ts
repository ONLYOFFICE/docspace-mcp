/**
 * @module meta
 */

export const name = "@onlyoffice/docspace-mcp"
export const version = "3.4.0"

// scripts/build-app.ts replaces the identifier when it bundles the server; it
// is undeclared when the sources run directly.
declare const ONLYOFFICE_DISTRIBUTION: string | undefined

export const distribution = typeof ONLYOFFICE_DISTRIBUTION === "string" ? ONLYOFFICE_DISTRIBUTION : "js"
