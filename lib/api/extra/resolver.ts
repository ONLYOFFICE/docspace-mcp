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
    const ue: Error[] = []

    for (const s of states) {
      if (s.id === undefined) {
        continue
      }

      // The latest status of the operation, or the one it started with when the
      // portal has not listed it since.
      const lo = operations.find((x) => x.id === s.id) ?? ops.find((x) => x.id === s.id)
      const pn = lo ? processedNote(lo) : ""

      if (s.error !== undefined && s.error !== "") {
        let m = s.error

        if (!s.done) {
          m = `${sentence(m)} The operation did not finish after ${this.limit} status checks, so it may still be running on the portal.`
        }

        if (pn !== "") {
          m = sentence(m) + pn
        }

        u.push(s.id)
        ue.push(new Error(`Operation ${s.id}: ${m}`))
        continue
      }

      if (!s.done) {
        u.push(s.id)
        ue.push(new Error(`Operation ${s.id} did not finish after ${this.limit} status checks. It may still be running on the portal.${pn}`))
      }
    }

    if (err) {
      const e = new ResolverResponseError("Resolving operations.", {cause: err})
      e.response = s
      e.unresolved = u
      return error(e)
    }

    if (u.length !== 0) {
      // Keep the reason of each operation, such as the error message that the
      // portal reports for a file it refuses to copy.
      const m = `${u.length} out of ${ops.length} operations are unresolved.`
      const e = new ResolverResponseError(m, {cause: new AggregateError(ue)})
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

const processedListLimit = 10

/**
 * Describes what an unresolved operation has done before it stopped, such as
 * the files it copied before the portal refused another one, so that the
 * caller does not repeat the call blindly.
 */
function processedNote(o: Operation): string {
  const es: string[] = []

  for (const [k, xs] of [["file", o.files], ["folder", o.folders]] as const) {
    if (!xs || xs.length === 0) {
      continue
    }

    const ns: string[] = []

    for (const x of xs.slice(0, processedListLimit)) {
      const t = x.title ?? "untitled"
      ns.push(x.id === undefined ? t : `${t} (${String(x.id)})`)
    }

    let e = `${xs.length} ${k}${xs.length === 1 ? "" : "s"}: ${ns.join(", ")}`

    if (xs.length > processedListLimit) {
      e += ` and ${xs.length - processedListLimit} more`
    }

    es.push(e)
  }

  if (es.length === 0) {
    return ""
  }

  return ` Before it stopped, the operation processed ${es.join("; and ")}. Check the destination before calling the tool again.`
}

function sentence(s: string): string {
  const t = s.trim()
  return /[.!?]$/.test(t) ? t : `${t}.`
}

// The portal sets the error of an operation while the operation still runs,
// such as when it refuses one of several files to copy and goes on copying the
// rest, so an operation is done only when it finishes.
function isDone(o: Operation): boolean {
  return isFinished(o)
}

function isFinished(o: Operation): boolean {
  return o.progress !== undefined && o.progress === 100 ||
    o.finished !== undefined && o.finished
}
