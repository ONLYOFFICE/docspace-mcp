/**
 * @module util/context
 */

import * as asyncHooks from "node:async_hooks"

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
