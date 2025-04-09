import {setTimeout} from "node:timers/promises"
import type * as z from "zod"
import type {FileOperationDtoSchema} from "./client/schemas.ts"
import type {Response as ClientResponse} from "./client.ts"
import type {Result} from "../ext/result.ts"
import {error, ok, safeAsync} from "../ext/result.ts"

export type Operation = z.output<typeof FileOperationDtoSchema>

export type OperationStatusesCallback =
	(s: AbortSignal) => Promise<Result<[Operation[], ClientResponse], Error>>

class State {
	id: string | undefined
	error: string | undefined
	done = false
}

export class Resolver {
	limit = 20
	delay = 100

	private cb: OperationStatusesCallback

	constructor(cb: OperationStatusesCallback) {
		this.cb = cb
	}

	async resolve(signal: AbortSignal, ...ops: Operation[]): Promise<Result<Response, Error>> {
		if (ops.length === 0) {
			return error(new Error("No operations to sync."))
		}

		let states: State[] = []

		for (let o of ops) {
			let s = new State()
			s.id = o.id
			s.error = o.error
			s.done = isDone(o)

			states.push(s)
		}

		let limit = this.limit
		let delay = this.delay

		let responses: ClientResponse[] = []
		let operations: Operation[] = []

		let err: Error | undefined

		while (limit > 0) {
			let r = await this.cb(signal)
			if (r.err) {
				err = new Error("Calling operation statuses callback.", {cause: r.err})
				break
			}

			let [ops, res] = r.v

			responses.push(res)

			for (let s of states) {
				if (s.id === undefined) {
					continue
				}

				for (let o of ops) {
					if (o.id === undefined) {
						continue
					}

					if (s.id === o.id) {
						s.error = o.error
						s.done = isDone(o)

						let i = -1

						for (let [j, x] of operations.entries()) {
							if (x.id === o.id) {
								i = j
								break
							}
						}

						if (i !== -1) {
							operations[i] = o
						} else {
							operations.push(o)
						}
					}
				}
			}

			let done = true

			for (let s of states) {
				if (!s.done) {
					done = false
					break
				}
			}

			if (done) {
				break
			}

			limit -= 1

			let t = await safeAsync(setTimeout, delay, undefined, {signal})
			if (t.err) {
				err = new Error("Setting timeout.", {cause: t.err})
				break
			}
		}

		let s = new Response()
		s.responses = responses
		s.operations = operations

		let u: string[] = []

		for (let s of states) {
			if (s.id === undefined) {
				continue
			}

			if (s.error !== undefined && s.error !== "" || !s.done) {
				u.push(s.id)
			}
		}

		if (err) {
			let e = new ErrorResponse("Resolving operations.", {cause: err})
			e.response = s
			e.unresolved = u
			return error(e)
		}

		if (u.length !== 0) {
			let m = `${u.length} out of ${ops.length} operations are unresolved.`
			let e = new ErrorResponse(m)
			e.response = s
			e.unresolved = u
			return error(e)
		}

		return ok(s)
	}
}

export class Response {
	responses: ClientResponse[] = []
	operations: Operation[] = []
}

// eslint-disable-next-line unicorn/custom-error-definition
export class ErrorResponse extends Error {
	response = new Response()
	unresolved: string[] = []

	constructor(message: string, options?: ErrorOptions) {
		super(message, options)
		this.name = "ErrorResponse"
	}
}

function isDone(o: Operation): boolean {
	return hasError(o) || isFinished(o)
}

function hasError(o: Operation): boolean {
	return o.error !== undefined && o.error !== ""
}

function isFinished(o: Operation): boolean {
	return o.progress !== undefined && o.progress === 100 ||
		o.finished !== undefined && o.finished
}
