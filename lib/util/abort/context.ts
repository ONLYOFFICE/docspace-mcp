/**
 * @module
 * @mergeModuleWith util/abort
 */

declare module "../context.ts" {
	// eslint-disable-next-line typescript/consistent-type-definitions
	interface Context {
		[signalKey]?: AbortSignal
	}
}

export const signalKey = Symbol("signal")
