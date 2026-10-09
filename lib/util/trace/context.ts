/**
 * @module
 * @mergeModuleWith util/trace
 */

declare module "../context.ts" {
  interface Context {
    [requestIdKey]?: string
  }
}

export const requestIdKey = Symbol("requestId")
