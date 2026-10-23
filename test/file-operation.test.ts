/**
 * @module test
 */

import assert from "node:assert/strict"
import events from "node:events"
import test from "node:test"
import * as core from "../lib/api/core.ts"
import * as apiExtra from "../lib/api/extra.ts"
import * as abort from "../lib/util/abort.ts"
import * as context from "../lib/util/context.ts"
import * as r from "../lib/util/result.ts"

// Answers each poll with the next of the given operation statuses, repeating
// the last one, until the operation with the "op" ID ends or fails, and returns
// the events the poller emitted for it.
async function poll(t: test.TestContext, ...ds: apiExtra.FileOperationDto[][]): Promise<string[]> {
  const res = new core.Response(new Request("http://localhost/api/2.0/files/fileops"), new Response())

  let i = 0

  const c: apiExtra.FileOperationPollerClient = {
    files: {
      getOperationStatuses() {
        const d = ds[Math.min(i, ds.length - 1)]
        i += 1
        return Promise.resolve(r.ok([d, res]))
      },
    },
  }

  const bus = new events.EventEmitter<apiExtra.FileOperationBusEventMap>()

  const fc: apiExtra.FileOperationPollerConfig = {
    interval: 1,
    bus,
    client: c,
  }

  const fp = new apiExtra.FileOperationPoller(fc)

  t.after(fp.close.bind(fp))

  fp.listen()

  const a: string[] = []

  const e = (resolve: () => void): void => {
    const onData = (id: string): void => {
      if (id === "op") {
        a.push("data")
      }
    }

    const onEnd = (id: string): void => {
      if (id === "op") {
        a.push("end")
        done()
      }
    }

    const onErr = (id: string, err: Error): void => {
      if (id === "op") {
        const m = err instanceof AggregateError ? err.errors.map((x: Error) => x.message) : [err.message]
        a.push(`error: ${m.join(", ")}`)
        done()
      }
    }

    const done = (): void => {
      bus.removeListener("data", onData)
      bus.removeListener("end", onEnd)
      bus.removeListener("error", onErr)
      resolve()
    }

    bus.addListener("data", onData)
    bus.addListener("end", onEnd)
    bus.addListener("error", onErr)
  }

  await new Promise<void>(e)

  return a
}

void test.suite("file operation poller", () => {
  void test("ends an operation that processed nothing but saved files", async(t) => {
    const d: apiExtra.FileOperationDto[] = [
      {id: "op", status: 2, processed: "0", finished: true, files: [{id: 1, title: "Report.docx"}]},
    ]

    assert.deepEqual(await poll(t, d), ["data", "end"])
  })

  void test("fails an operation that processed nothing and saved no files", async(t) => {
    const d: apiExtra.FileOperationDto[] = [
      {id: "op", status: 2, processed: "0", finished: true, files: []},
    ]

    assert.deepEqual(await poll(t, d), ["error: No items processed"])
  })

  void test("fails an operation that processed nothing and has no files", async(t) => {
    const d: apiExtra.FileOperationDto[] = [
      {id: "op", status: 2, processed: "0", finished: true},
    ]

    assert.deepEqual(await poll(t, d), ["error: No items processed"])
  })

  void test("fails an operation with its error alone when it processed nothing", async(t) => {
    const d: apiExtra.FileOperationDto[] = [
      {id: "op", status: 2, processed: "0", finished: true, error: "Error occurred in the Documents Service (convertation, error -3)"},
    ]

    assert.deepEqual(await poll(t, d), ["error: Error occurred in the Documents Service (convertation, error -3)"])
  })

  void test("ends an operation that processed items", async(t) => {
    const d: apiExtra.FileOperationDto[] = [
      {id: "op", status: 2, processed: "3", finished: true},
    ]

    assert.deepEqual(await poll(t, d), ["data", "end"])
  })

  void test("reports the progress of an operation before it ends", async(t) => {
    const a: apiExtra.FileOperationDto[] = [
      {id: "op", status: 1, processed: "0", finished: false},
    ]

    const b: apiExtra.FileOperationDto[] = [
      {id: "op", status: 2, processed: "0", finished: true, files: [{id: 1, title: "Report.docx"}]},
    ]

    assert.deepEqual(await poll(t, a, b), ["data", "data", "end"])
  })

  void test("polls without the signal of the request that started it", async(t) => {
    const res = new core.Response(new Request("http://localhost/api/2.0/files/fileops"), new Response())

    const signals: (AbortSignal | undefined)[] = []

    const c: apiExtra.FileOperationPollerClient = {
      files: {
        getOperationStatuses() {
          signals.push(context.get()[abort.signalKey])
          return Promise.resolve(r.ok([[], res]))
        },
      },
    }

    const bus = new events.EventEmitter<apiExtra.FileOperationBusEventMap>()

    const fc: apiExtra.FileOperationPollerConfig = {
      interval: 1,
      bus,
      client: c,
    }

    const fp = new apiExtra.FileOperationPoller(fc)

    t.after(fp.close.bind(fp))

    fp.listen()

    const onData = (): void => {}

    const ac = new AbortController()

    context.run({[abort.signalKey]: ac.signal}, () => {
      bus.addListener("data", onData)
    })

    await new Promise((resolve) => {
      setTimeout(resolve, 20)
    })

    bus.removeListener("data", onData)

    assert.ok(signals.length !== 0)
    assert.deepEqual(signals.filter(Boolean), [])
  })
})

// Starts an operation with the "op" ID through a caller that records the IDs
// it terminates, then waits for the operation the way a tool handler does.
async function call(bus: apiExtra.FileOperationBus, terminated: string[], timeout: number, fail = false): Promise<r.Result<apiExtra.FileOperationDto, Error>> {
  const res = new core.Response(new Request("http://localhost/api/2.0/files/fileops"), new Response())

  const c: apiExtra.FileOperationCallerClient = {
    files: {
      terminateOperation(id) {
        terminated.push(id)
        if (fail) {
          return Promise.resolve(r.error(new Error("Portal is down")))
        }
        return Promise.resolve(r.ok([[], res]))
      },
    },
  }

  const fc: apiExtra.FileOperationCallerConfig = {
    timeout,
    bus,
    client: c,
  }

  const cr = new apiExtra.FileOperationCaller(fc)

  const it = await cr.call(() => Promise.resolve(r.ok([{id: "op"}, res])))

  for await (const _ of it) {
    // Wait for the operation to finish.
  }

  return it.result()
}

void test.suite("file operation caller", () => {
  void test("terminates the operation when the timeout passes", async() => {
    const bus = new events.EventEmitter<apiExtra.FileOperationBusEventMap>()
    const terminated: string[] = []

    const rr = await call(bus, terminated, 10)

    assert.ok(rr.err instanceof DOMException)
    assert.equal(rr.err.name, "TimeoutError")
    assert.deepEqual(terminated, ["op"])
  })

  void test("terminates the operation when the signal of the request aborts", async() => {
    const bus = new events.EventEmitter<apiExtra.FileOperationBusEventMap>()
    const terminated: string[] = []

    const ac = new AbortController()

    const e = (resolve: (v: r.Result<apiExtra.FileOperationDto, Error>) => void): void => {
      const cb = (): void => {
        void call(bus, terminated, 0).then(resolve)
      }

      context.run({[abort.signalKey]: ac.signal}, cb)
    }

    const p = new Promise(e)

    setTimeout(() => {
      ac.abort(new DOMException("Request cancelled", "AbortError"))
    }, 10)

    const rr = await p

    assert.ok(rr.err instanceof DOMException)
    assert.equal(rr.err.message, "Request cancelled")
    assert.deepEqual(terminated, ["op"])
  })

  void test("does not start the operation when the signal of the request has already aborted", async() => {
    const res = new core.Response(new Request("http://localhost/api/2.0/files/fileops"), new Response())

    const terminated: string[] = []

    const c: apiExtra.FileOperationCallerClient = {
      files: {
        terminateOperation(id) {
          terminated.push(id)
          return Promise.resolve(r.ok([[], res]))
        },
      },
    }

    const bus = new events.EventEmitter<apiExtra.FileOperationBusEventMap>()

    const fc: apiExtra.FileOperationCallerConfig = {
      timeout: 0,
      bus,
      client: c,
    }

    const cr = new apiExtra.FileOperationCaller(fc)

    let started = false

    const fn: apiExtra.FileOperationFn = () => {
      started = true
      return Promise.resolve(r.ok([{id: "op"}, res]))
    }

    const ac = new AbortController()
    ac.abort(new DOMException("Request cancelled", "AbortError"))

    const e = (resolve: (v: apiExtra.FileOperationIter) => void): void => {
      const cb = (): void => {
        void cr.call(fn).then(resolve)
      }

      context.run({[abort.signalKey]: ac.signal}, cb)
    }

    const it = await new Promise(e)

    for await (const _ of it) {
      // Wait for the operation to finish.
    }

    const rr = it.result()

    assert.ok(rr.err instanceof DOMException)
    assert.equal(rr.err.message, "Request cancelled")
    assert.equal(started, false)
    assert.deepEqual(terminated, [])
    assert.equal(bus.listenerCount("data"), 0)
  })

  void test("does not terminate the operations of the session when polling fails", async() => {
    const bus = new events.EventEmitter<apiExtra.FileOperationBusEventMap>()
    const terminated: string[] = []

    const p = Promise.all([call(bus, terminated, 0), call(bus, terminated, 0)])

    setTimeout(() => {
      bus.emit("error", "", new Error("Getting operation statuses"))
    }, 10)

    const rs = await p

    for (const rr of rs) {
      assert.ok(rr.err)
      assert.equal(rr.err.message, "Getting operation statuses")
    }

    assert.deepEqual(terminated, [])
  })

  void test("terminates the operation that starts after the timeout passes", async() => {
    const res = new core.Response(new Request("http://localhost/api/2.0/files/fileops"), new Response())

    const terminated: string[] = []

    const c: apiExtra.FileOperationCallerClient = {
      files: {
        terminateOperation(id) {
          terminated.push(id)
          return Promise.resolve(r.ok([[], res]))
        },
      },
    }

    const bus = new events.EventEmitter<apiExtra.FileOperationBusEventMap>()

    const fc: apiExtra.FileOperationCallerConfig = {
      timeout: 10,
      bus,
      client: c,
    }

    const cr = new apiExtra.FileOperationCaller(fc)

    // The call that starts the operation outlives the timeout.
    const fn: apiExtra.FileOperationFn = () => {
      const e = (resolve: (v: r.Result<[apiExtra.FileOperationDto, core.Response], Error>) => void): void => {
        setTimeout(() => {
          resolve(r.ok([{id: "op"}, res]))
        }, 50)
      }

      return new Promise(e)
    }

    const it = await cr.call(fn)

    for await (const _ of it) {
      // Wait for the operation to finish.
    }

    const rr = it.result()

    assert.ok(rr.err instanceof DOMException)
    assert.equal(rr.err.name, "TimeoutError")
    assert.deepEqual(terminated, ["op"])
  })

  void test("reports the error of a failed termination", async() => {
    const bus = new events.EventEmitter<apiExtra.FileOperationBusEventMap>()
    const terminated: string[] = []

    const rr = await call(bus, terminated, 10, true)

    assert.ok(rr.err instanceof AggregateError)
    assert.ok(rr.err.errors[0] instanceof DOMException)
    assert.equal(rr.err.errors[1].message, "Terminating operation")
    assert.deepEqual(terminated, ["op"])
  })

  void test("does not terminate an operation that ended", async() => {
    const bus = new events.EventEmitter<apiExtra.FileOperationBusEventMap>()
    const terminated: string[] = []

    const p = call(bus, terminated, 1000)

    setTimeout(() => {
      bus.emit("data", "op", {id: "op", status: 2, finished: true})
      bus.emit("end", "op")
    }, 10)

    const rr = await p

    assert.ok(rr.err === undefined)
    assert.deepEqual(rr.v, {id: "op", status: 2, finished: true})
    assert.deepEqual(terminated, [])
  })

  void test("does not terminate an operation that failed", async() => {
    const bus = new events.EventEmitter<apiExtra.FileOperationBusEventMap>()
    const terminated: string[] = []

    const p = call(bus, terminated, 1000)

    setTimeout(() => {
      bus.emit("error", "op", new Error("Error occurred in the Documents Service (convertation, error -3)"))
    }, 10)

    const rr = await p

    assert.ok(rr.err)
    assert.deepEqual(terminated, [])
  })
})
