/**
 * @module
 * @mergeModuleWith dist
 */

import * as z from "zod"

export const ManifestOptionSchema = z.object({
	type: z.string(),
	title: z.string(),
	description: z.string(),
	required: z.boolean(),
	default: z.unknown(),
})

export const ManifestToolSchema = z.object({
	name: z.string(),
	description: z.string(),
})

export const ManifestConfigSchema = z.looseObject({
	env: z.record(z.string(), z.string()),
})

export const ManifestServerSchema = z.looseObject({
	mcp_config: ManifestConfigSchema,
})

export const ManifestSchema = z.looseObject({
	$schema: z.string(),
	version: z.string(),
	documentation: z.string(),
	server: ManifestServerSchema,
	tools: z.array(ManifestToolSchema),
	user_config: z.record(z.string(), ManifestOptionSchema),
})

export type ManifestOption = z.infer<typeof ManifestOptionSchema>

export type ManifestTool = z.infer<typeof ManifestToolSchema>

export type ManifestConfig = z.infer<typeof ManifestConfigSchema>

export type ManifestServer = z.infer<typeof ManifestServerSchema>

export type Manifest = z.infer<typeof ManifestSchema>
