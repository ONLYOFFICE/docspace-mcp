/**
 * @module
 * @mergeModuleWith util/forwarded
 */

declare module "../context.ts" {
	// eslint-disable-next-line typescript/consistent-type-definitions
	interface Context {
		[forwardedForKey]?: string
		[realIpKey]?: string
	}
}

export const forwardedForKey = Symbol("forwardedFor")
export const realIpKey = Symbol("realIp")
