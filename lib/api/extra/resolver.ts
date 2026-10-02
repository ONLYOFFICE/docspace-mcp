/**
 * @module
 * @mergeModuleWith api/extra
 */

import {setTimeout} from "node:timers/promises"
import type * as z from "zod"
import * as abort from "../../util/abort.ts"
import * as context from "../../util/context.ts"
import type {Result} from "../../util/result.ts"
import {error, ok, safeAsync} from "../../util/result.ts"
import type * as core from "../core.ts"

export type Operation = z.output<typeof core.FileOperationDtoSchema>

class State {
  id: string | undefined
  error: string | undefined
  done = false
}

export type ResolverClient = {
  files: ResolverFilesService
}

export type ResolverFilesService = {
  getOperationStatuses(): Promise<Result<[Operation[], core.Response], Error>>
}

export class Resolver {
  limit = 20
  delay = 100

  private client: ResolverClient

  constructor(client: ResolverClient) {
    this.client = client
  }

  async resolve(...ops: Operation[]): Promise<Result<ResolverResponse, Error>> {
    const ctx = context.get()

    if (ops.length === 0) {
      return error(new Error("No operations to sync."))
    }

    const states: State[] = []

    for (const o of ops) {
      const s = new State()
      s.id = o.id
      s.error = o.error
      s.done = isDone(o)

      states.push(s)
    }

    let limit = this.limit
    const delay = this.delay

    const responses: core.Response[] = []
    const operations: Operation[] = []

    let err: Error | undefined

    while (limit > 0) {
      const r = await this.client.files.getOperationStatuses()
      if (r.err) {
        err = new Error("Calling operation statuses callback.", {cause: r.err})
        break
      }

      const [ops, res] = r.v

      responses.push(res)

      for (const s of states) {
        if (s.id === undefined) {
          continue
        }

        for (const o of ops) {
          if (o.id === undefined) {
            continue
          }

          if (s.id === o.id) {
            s.error = o.error
            s.done = isDone(o)

            let i = -1

            for (const [j, x] of operations.entries()) {
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

      for (const s of states) {
        if (!s.done) {
          done = false
          break
        }
      }

      if (done) {
        break
      }

      limit -= 1

      const t = await safeAsync(setTimeout, delay, undefined, {signal: ctx[abort.signalKey]})
      if (t.err) {
        err = new Error("Setting timeout.", {cause: t.err})
        break
      }
    }

    const s = new ResolverResponse()
    s.responses = responses
    s.operations = operations

    const u: string[] = []

    for (const s of states) {
      if (s.id === undefined) {
        continue
      }

      if (s.error !== undefined && s.error !== "" || !s.done) {
        u.push(s.id)
      }
    }

    if (err) {
      const e = new ResolverResponseError("Resolving operations.", {cause: err})
      e.response = s
      e.unresolved = u
      return error(e)
    }

    if (u.length !== 0) {
      const m = `${u.length} out of ${ops.length} operations are unresolved.`
      const e = new ResolverResponseError(m)
      e.response = s
      e.unresolved = u
      return error(e)
    }

    return ok(s)
  }
}

export class ResolverResponse {
  responses: core.Response[] = []
  operations: Operation[] = []
}

export class ResolverResponseError extends Error {
  response = new ResolverResponse()
  unresolved: string[] = []

  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = "ResolverResponseError"
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
