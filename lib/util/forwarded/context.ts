/**
 * @module
 * @mergeModuleWith util/forwarded
 */

declare module "../context.ts" {
  interface Context {
    [forwardedForKey]?: string
    [realIpKey]?: string
  }
}

export const forwardedForKey = Symbol("forwardedFor")
export const realIpKey = Symbol("realIp")
