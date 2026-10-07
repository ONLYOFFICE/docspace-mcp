/**
 * @module test
 */

import assert from "node:assert/strict"
import events from "node:events"
import test from "node:test"
import * as core from "../lib/api/core.ts"
import * as apiExtra from "../lib/api/extra.ts"
import * as r from "../lib/util/result.ts"

// Answers each poll with the next of the given operation statuses, repeating
// the last one, until the operation with the "op" ID ends or fails, and returns
// the events the poller emitted for it.
async function poll(t: test.TestContext, ...ds: apiExtra.FileOperationDto[][]): Promise<string[]> {
  let res = new core.Response(new Request("http://localhost/api/2.0/files/fileops"), new Response())

  let i = 0

  let c: apiExtra.FileOperationPollerClient = {
    files: {
      getOperationStatuses() {
        let d = ds[Math.min(i, ds.length - 1)]
        i += 1
        return Promise.resolve(r.ok([d, res]))
      },
    },
  }

  let bus = new events.EventEmitter<apiExtra.FileOperationBusEventMap>()

  let fc: apiExtra.FileOperationPollerConfig = {
    interval: 1,
    bus,
    client: c,
  }

  let fp = new apiExtra.FileOperationPoller(fc)

  t.after(fp.close.bind(fp))

  fp.listen()

  let a: string[] = []

  let e = (resolve: () => void): void => {
    let onData = (id: string): void => {
      if (id === "op") {
        a.push("data")
      }
    }

    let onEnd = (id: string): void => {
      if (id === "op") {
        a.push("end")
        done()
      }
    }

    let onErr = (id: string, err: Error): void => {
      if (id === "op") {
        let m = err instanceof AggregateError ? err.errors.map((x: Error) => x.message) : [err.message]
        a.push(`error: ${m.join(", ")}`)
        done()
      }
    }

    let done = (): void => {
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
    let d: apiExtra.FileOperationDto[] = [
      {id: "op", status: 2, processed: "0", finished: true, files: [{id: 1, title: "Report.docx"}]},
    ]

    assert.deepEqual(await poll(t, d), ["data", "end"])
  })

  void test("fails an operation that processed nothing and saved no files", async(t) => {
    let d: apiExtra.FileOperationDto[] = [
      {id: "op", status: 2, processed: "0", finished: true, files: []},
    ]

    assert.deepEqual(await poll(t, d), ["error: No items processed"])
  })

  void test("fails an operation that processed nothing and has no files", async(t) => {
    let d: apiExtra.FileOperationDto[] = [
      {id: "op", status: 2, processed: "0", finished: true},
    ]

    assert.deepEqual(await poll(t, d), ["error: No items processed"])
  })

  void test("ends an operation that processed items", async(t) => {
    let d: apiExtra.FileOperationDto[] = [
      {id: "op", status: 2, processed: "3", finished: true},
    ]

    assert.deepEqual(await poll(t, d), ["data", "end"])
  })

  void test("reports the progress of an operation before it ends", async(t) => {
    let a: apiExtra.FileOperationDto[] = [
      {id: "op", status: 1, processed: "0", finished: false},
    ]

    let b: apiExtra.FileOperationDto[] = [
      {id: "op", status: 2, processed: "0", finished: true, files: [{id: 1, title: "Report.docx"}]},
    ]

    assert.deepEqual(await poll(t, a, b), ["data", "data", "end"])
  })
})
