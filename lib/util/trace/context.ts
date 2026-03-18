/**
 * @module
 * @mergeModuleWith util/trace
 */

declare module "../context.ts" {
	// eslint-disable-next-line typescript/consistent-type-definitions
	interface Context {
		[requestIdKey]?: string
	}
}

export const requestIdKey = Symbol("requestId")
