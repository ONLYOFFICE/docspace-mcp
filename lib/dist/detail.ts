/**
 * @module
 * @mergeModuleWith dist
 */

import * as z from "zod"

export const DetailValueSchema = z.object({
	description: z.string(),
	isRequired: z.boolean(),
	format: z.enum(["string", "number", "boolean"]),
	isSecret: z.boolean(),
	default: z.string(),
	choices: z.array(z.string()),
	name: z.string(),
})

export const DetailTransportSchema = z.looseObject({
	type: z.enum(["stdio", "sse", "streamable-http"]),
	url: z.string().optional(),
	headers: z.array(DetailValueSchema).optional(),
})

export const DetailPackageSchema = z.looseObject({
	registryType: z.enum(["mcpb", "npm", "oci"]),
	identifier: z.string(),
	version: z.string().optional(),
	fileSha256: z.string().optional(),
	transport: DetailTransportSchema,
	environmentVariables: z.array(DetailValueSchema),
})

export const DetailSchema = z.looseObject({
	$schema: z.string(),
	version: z.string(),
	packages: z.array(DetailPackageSchema),
	remotes: z.array(DetailTransportSchema),
})

export type DetailValue = z.infer<typeof DetailValueSchema>

export type DetailTransport = z.infer<typeof DetailTransportSchema>

export type DetailPackage = z.infer<typeof DetailPackageSchema>

export type Detail = z.infer<typeof DetailSchema>
