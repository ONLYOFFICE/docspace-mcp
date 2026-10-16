/**
 * @module
 * @mergeModuleWith dist
 */

import * as z from "zod"

let url = z.url({protocol: /^https$/}).max(1024)

let path = z.string().startsWith("./")

export const PluginInterfaceSchema = z.looseObject({
  displayName: z.string().min(1).max(30),
  shortDescription: z.string().min(1).max(30),
  longDescription: z.string().min(1).max(4000),
  developerName: z.string().min(1).max(80),
  category: z.string().min(1),
  capabilities: z.array(z.string().min(1).max(120)).max(20),
  websiteURL: url,
  supportURL: url,
  privacyPolicyURL: url,
  termsOfServiceURL: url,
  defaultPrompt: z.array(z.string().min(1).max(128)).max(3).optional(),
  composerIcon: path,
  logo: path,
})

export const PluginOpenaiSchema = z.looseObject({
  interface: PluginInterfaceSchema,
})

export const PluginSchema = z.looseObject({
  $schema: z.string(),
  name: z.string().max(64).regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/),
  version: z.string().regex(/^\d+\.\d+\.\d+$/),
  description: z.string().min(1).max(4000),
  author: z.looseObject({
    name: z.string().min(1),
  }),
  extensions: z.looseObject({
    "com.openai": PluginOpenaiSchema,
  }),
})

export const PluginAuthSchema = z.looseObject({
  type: z.enum(["none", "oauth", "mixed", "api_key"]),
})

export const PluginServerSchema = z.looseObject({
  type: z.enum(["streamable-http", "sse"]),
  url,
  extensions: z.looseObject({
    "com.openai": z.looseObject({
      auth: PluginAuthSchema,
    }),
  }),
})

export const PluginMcpSchema = z.looseObject({
  $schema: z.string(),
  mcpServers: z.record(z.string(), PluginServerSchema),
})

export type PluginInterface = z.infer<typeof PluginInterfaceSchema>

export type PluginOpenai = z.infer<typeof PluginOpenaiSchema>

export type Plugin = z.infer<typeof PluginSchema>

export type PluginAuth = z.infer<typeof PluginAuthSchema>

export type PluginServer = z.infer<typeof PluginServerSchema>

export type PluginMcp = z.infer<typeof PluginMcpSchema>
