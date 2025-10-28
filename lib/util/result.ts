/**
 * (c) Copyright Ascensio System SIA 2025
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @license
 */

// This module is inspired by the following implementation:
// https://github.com/supermacro/neverthrow/

/**
 * Result is an implementation of the Result type known from other languages
 * such as Rust, Swift, etc. It has its limitations, and its typing can lead to
 * failures if not following two techniques:
 *
 * 1. The error must always be something that cannot be typecast;
 * 2. The access to the ok must always be through error checking.
 *
 * @example
 *
 * ```ts
 * let r = fn() // Result<string, globalThis.Error>
 * if (r.err) {
 *   let _ = r  // Error<string, globalThis.Error>
 * } else {
 *   let _ = r  // Ok<string, globalThis.Error>
 * }
 * ```
 */
export type Result<V, E> = Ok<V, E> | Error<V, E>

/**
 * Ok is the result of a successful operation.
 */
export interface Ok<V, _> {
	v: V
	err: undefined
}

/**
 * Error is the result of a failed operation.
 */
export interface Error<_, E> {
	v: undefined
	err: E
}

/**
 * Creates a new Ok result.
 *
 * @param v The value to wrap in the Ok result.
 * @returns A new Ok result.
 */
export function ok<V, E = never>(v: V): Ok<V, E>

// eslint-disable-next-line typescript/no-invalid-void-type
export function ok<E = never>(v: void): Ok<void, E>

export function ok<V, E = never>(v: V): Ok<V, E> {
	return {
		v,
		err: undefined,
	}
}

/**
 * Creates a new Error result.
 *
 * @param err The error to wrap in the Error result.
 * @returns A new Error result.
 */
export function error<V = never, E = unknown>(err: E): Error<V, E> {
	return {
		v: undefined,
		err,
	}
}

/**
 * Calls the function and wraps its return value in a Result.
 *
 * @param fn
 *   The function to call.
 *
 * @param args
 *   The arguments to pass to the function.
 *
 * @returns
 *   A Result object containing the result of the function call or an error if
 *   the function call failed.
 */
export function safeSync<
	A extends unknown[],
	R,
>(
	fn: (...args: A) => R,
	...args: A
): Result<R, globalThis.Error> {
	try {
		return ok(fn(...args))
	} catch (err) {
		if (err instanceof Error) {
			return error(err)
		}
		return error(new Error("Unknown error.", {cause: err}))
	}
}

/**
 * Calls the async function and wraps its return value in a Result.
 *
 * @param fn
 *   The async function to call.
 *
 * @param args
 *   The arguments to pass to the function.
 *
 * @returns
 *   A Result object containing the result of the function call or an error if
 *   the function call failed.
 */
export async function safeAsync<
	A extends unknown[],
	R,
>(
	fn: (...args: A) => PromiseLike<R>,
	...args: A
): Promise<Result<Awaited<R>, globalThis.Error>> {
	try {
		return ok(await Promise.resolve(fn(...args)))
	} catch (err) {
		if (err instanceof Error) {
			return error(err)
		}
		return error(new Error("Unknown error.", {cause: err}))
	}
}

/**
 * Calls the constructor and wraps its return value in a Result.
 *
 * @param fn
 *   The constructor to call.
 *
 * @param args
 *   The arguments to pass to the constructor.
 *
 * @returns
 *   A Result object containing the result of the constructor call or an error
 *   if the constructor call failed.
 */
export function safeNew<
	A extends unknown[],
	R,
>(
	fn: new (...args: A) => R,
	...args: A
): Result<R, globalThis.Error> {
	try {
		// eslint-disable-next-line new-cap
		return ok(new fn(...args))
	} catch (err) {
		if (err instanceof Error) {
			return error(err)
		}
		return error(new Error("Unknown error.", {cause: err}))
	}
}
