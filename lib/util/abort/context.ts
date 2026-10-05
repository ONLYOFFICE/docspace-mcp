/**
 * @module
 * @mergeModuleWith util/abort
 */

declare module "../context.ts" {
  interface Context {
    [signalKey]?: AbortSignal
  }
}

export const signalKey = Symbol("signal")
