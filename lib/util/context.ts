/**
 * @module util/context
 */

import * as asyncHooks from "node:async_hooks"

// Use interface declaration to allow Context to be extended from other files.
// eslint-disable-next-line typescript/consistent-indexed-object-style, typescript/consistent-type-definitions
export interface Context {
	[key: symbol]: unknown
}

const o: asyncHooks.AsyncLocalStorageOptions = {
	name: "context",
}

const s = new asyncHooks.AsyncLocalStorage<Context>(o)

export function run(ctx: Context, cb: () => void): void {
	s.run({...s.getStore(), ...ctx}, cb)
}

export function get(): Context {
	let ctx = s.getStore()
	if (!ctx) {
		ctx = {}
	}
	return ctx
}
