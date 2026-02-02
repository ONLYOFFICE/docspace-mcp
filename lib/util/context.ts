/**
 * @module util/context
 */

import * as asyncHooks from "node:async_hooks"

// Use interface declaration to allow Context to be extended from other files.
// eslint-disable-next-line typescript/consistent-type-definitions
export interface Context {}

const s = new asyncHooks.AsyncLocalStorage<Context>({
	name: "context",
})

export function run(c: Context, cb: () => void): void {
	s.run(c, cb)
}

export function get(): Context | undefined {
	return s.getStore()
}
