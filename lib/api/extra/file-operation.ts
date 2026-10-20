/**
 * @module
 * @mergeModuleWith api/extra
 */

import type events from "node:events"
import timers from "node:timers"
import type * as z from "zod"
import * as abort from "../../util/abort.ts"
import * as context from "../../util/context.ts"
import * as r from "../../util/result.ts"
import type * as core from "../core.ts"

export type FileOperationDto = z.output<typeof core.FileOperationDtoSchema>

export type FileOperationBus = events<FileOperationBusEventMap>

export type FileOperationBusEventMap = FileOperationBusBaseEventMap & FileOperationBusExtendedEventMap

export type FileOperationBusBaseEventMap = {
  data: Parameters<FileOperationBusDataListener>
  end: Parameters<FileOperationBusEndListener>
  error: Parameters<FileOperationBusErrorListener>
}

export type FileOperationBusExtendedEventMap = {
  newListener: Parameters<FileOperationBusNewListenerListener>
  removeListener: Parameters<FileOperationBusRemoveListenerListener>
}

export type FileOperationBusDataListener = (id: string, data: FileOperationDto) => void

export type FileOperationBusEndListener = (id: string) => void

export type FileOperationBusErrorListener = (id: string, err: Error) => void

export type FileOperationBusNewListenerListener = (...args: Parameters<FileOperationBusNewListenerBaseEventListener> | ["newListener", Parameters<FileOperationBusNewListenerBaseEventListener>]) => void

export type FileOperationBusNewListenerBaseEventListener = (...args: {[K in keyof FileOperationBusBaseEventMap]: [K, ...FileOperationBusBaseEventMap[K]]}[keyof FileOperationBusBaseEventMap]) => void

export type FileOperationBusRemoveListenerListener = (...args: Parameters<FileOperationBusRemoveListenerBaseEventListener> | ["removeListener", Parameters<FileOperationBusRemoveListenerBaseEventListener>]) => void

export type FileOperationBusRemoveListenerBaseEventListener = (...args: {[K in keyof FileOperationBusBaseEventMap]: [K, ...FileOperationBusBaseEventMap[K]]}[keyof FileOperationBusBaseEventMap]) => void

export type FileOperationPollerConfig = {
  interval: number
  bus: FileOperationBus
  client: FileOperationPollerClient
}

export type FileOperationPollerClient = {
  files: FileOperationPollerClientFileService
}

export type FileOperationPollerClientFileService = {
  getOperationStatuses(): Promise<r.Result<[FileOperationDto[], core.Response], Error>>
}

export class FileOperationPoller {
  private interval: number
  private bus: FileOperationBus
  private client: FileOperationPollerClient

  private listening = false
  private controller = new AbortController()

  private boundHandleNewListener = this.handleNewListener.bind(this)
  private boundHandleRemoveListener = this.handleRemoveListener.bind(this)

  constructor(config: FileOperationPollerConfig) {
    this.interval = config.interval
    this.bus = config.bus
    this.client = config.client

    this.controller.abort(new DOMException("Not polling", "AbortError"))
  }

  listen(): void {
    if (this.listening) {
      return
    }

    this.bus.addListener("newListener", this.boundHandleNewListener)
    this.bus.addListener("removeListener", this.boundHandleRemoveListener)

    this.listening = true
  }

  close(): void {
    if (!this.listening) {
      return
    }

    this.controller.abort(new DOMException("Poller closed", "AbortError"))

    this.bus.removeListener("newListener", this.boundHandleNewListener)
    this.bus.removeListener("removeListener", this.boundHandleRemoveListener)

    this.listening = false
  }

  private handleNewListener(...p: Parameters<FileOperationBusNewListenerListener>): void {
    const [e] = p

    if (this.controller.signal.aborted && e === "data") {
      const c = new AbortController()

      let t: NodeJS.Timeout | undefined

      const onAbort = (): void => {
        clearTimeout(t)

        c.signal.removeEventListener("abort", onAbort)
      }

      const onTick = (): void => {
        void (async() => {
          await this.poll()

          if (!c.signal.aborted) {
            t = timers.setTimeout(onTick, this.interval)
          }
        })()
      }

      c.signal.addEventListener("abort", onAbort)

      // The poll serves every caller, so it must not follow the signal of the
      // request whose listener happened to start it.
      context.run({[abort.signalKey]: undefined}, () => {
        t = timers.setTimeout(onTick, this.interval)
      })

      this.controller = c
    }
  }

  private handleRemoveListener(): void {
    if (!this.controller.signal.aborted && this.bus.listenerCount("data") === 0) {
      this.controller.abort(new DOMException("No data listeners", "AbortError"))
    }
  }

  private async poll(): Promise<void> {
    const g = await this.client.files.getOperationStatuses()
    if (g.err) {
      this.bus.emit("error", "", new Error("Getting operation statuses", {cause: g.err}))
      return
    }

    const [d] = g.v

    for (const e of d) {
      if (!e.id) {
        continue
      }

      const errs: Error[] = []

      if (e.error) {
        errs.push(new Error(e.error))
      }

      // A document builder run reports nothing processed even when it saves
      // files, so the saved files are what tell it from an empty operation. A
      // failed operation has processed nothing too, which says nothing new.
      if (!e.error && e.status && e.status === 2 && e.processed && e.processed === "0" && !(Array.isArray(e.files) && e.files.length !== 0)) {
        errs.push(new Error("No items processed"))
      }

      if (errs.length !== 0) {
        this.bus.emit("error", e.id, new AggregateError(errs, "Checking operation"))
        continue
      }

      switch (e.status) {
      case 0:
      case 1:
        this.bus.emit("data", e.id, e)
        break
      case 2:
        this.bus.emit("data", e.id, e)
        this.bus.emit("end", e.id)
        break
      default:
        break
      }
    }
  }
}

export type FileOperationIter = AsyncIterator<FileOperationDto> & AsyncIterable<FileOperationDto> & {
  result(): r.Result<FileOperationDto, Error>
}

export type FileOperationFn = () => PromiseLike<r.Result<[FileOperationDto, core.Response], Error>>

export type FileOperationCallerConfig = {
  timeout: number
  bus: FileOperationBus
  client: FileOperationCallerClient
}

export type FileOperationCallerClient = {
  files: FileOperationCallerClientFileService
}

export type FileOperationCallerClientFileService = {
  terminateOperation(id: string): Promise<r.Result<[FileOperationDto[], core.Response], Error>>
}

// The time to wait for the portal to terminate an abandoned operation.
const terminateTimeout = 10000

export class FileOperationCaller {
  private timeout: number
  private bus: FileOperationBus
  private client: FileOperationCallerClient

  constructor(config: FileOperationCallerConfig) {
    this.timeout = config.timeout
    this.bus = config.bus
    this.client = config.client
  }

  // Waits for the operation until it ends, the timeout passes or the signal of
  // the request aborts. An operation that is no longer waited for is
  // terminated, so that it neither saves results nobody receives nor blocks
  // the next operations of the user.
  async call(fn: FileOperationFn): Promise<FileOperationIter> {
    let fid = ""
    let stopped = false
    let closed = false
    const buf: FileOperationDto[] = []
    let wake = (): void => {}
    const re = r.ok() as unknown as r.Result<FileOperationDto, Error>

    // Resolves with the ID of the operation once the call that starts it ends,
    // or with an empty string when the call fails.
    let started = (_: string): void => {}

    const se = (res: (id: string) => void): void => {
      started = res
    }

    const sp = new Promise<string>(se)

    const it: FileOperationIter = {
      [Symbol.asyncIterator]() {
        return it
      },

      async next() {
        if (!closed && buf.length === 0) {
          const e = (res: () => void): void => {
            wake = res
          }

          await new Promise<void>(e)
        }

        let ir: IteratorResult<FileOperationDto, undefined> | undefined

        const v = buf.shift()

        if (v) {
          ir = {
            done: false,
            value: v,
          }
        } else {
          ir = {
            done: true,
            value: undefined,
          }
        }

        return ir
      },

      // eslint-disable-next-line @typescript-eslint/require-await
      async return() {
        close()

        const ir: IteratorResult<unknown, unknown> = {
          done: true,
          value: undefined,
        }

        return ir
      },

      result() {
        return {...re}
      },
    }

    const ac = new abort.Controller()

    const s = context.get()[abort.signalKey]
    if (s) {
      ac.withSignal(s)
    }

    if (this.timeout) {
      ac.withSignal(AbortSignal.timeout(this.timeout))
    }

    const onAbort = (): void => {
      abandon(ac.signal.reason as Error)
    }

    // A failed poll says nothing about the operation itself and is reported to
    // every caller of the session, so the operation is left running.
    const onErr = (id: string, err: Error): void => {
      if (fid && id === fid || !id) {
        close(err)
      }
    }

    const onData = (id: string, data: FileOperationDto): void => {
      if (fid && id === fid) {
        buf.push(data)
        re.v = data
        wake()
      }
    }

    const onEnd = (id: string): void => {
      if (fid && id === fid) {
        close()
      }
    }

    const stop = (): void => {
      ac.signal.removeEventListener("abort", onAbort)

      this.bus.removeListener("error", onErr)
      this.bus.removeListener("data", onData)
      this.bus.removeListener("end", onEnd)

      ac.clear()

      stopped = true
    }

    const close = (err?: Error): void => {
      if (stopped) {
        return
      }

      stop()

      if (err) {
        re.err = err
      }

      closed = true

      wake()
    }

    // The iterator stays open until the termination ends, so that the error
    // of the termination reaches the result as well. An operation abandoned
    // while the call that starts it is still in flight may start anyway, so
    // the termination waits for its ID.
    const abandon = (err: Error): void => {
      if (stopped) {
        return
      }

      stop()

      void (async() => {
        re.err = err

        let id = fid
        if (!id) {
          id = await sp
        }

        if (id) {
          const tr = await this.terminate(id)
          if (tr.err) {
            re.err = new AggregateError([err, new Error("Terminating operation", {cause: tr.err})])
          }
        }

        closed = true

        wake()
      })()
    }

    ac.signal.addEventListener("abort", onAbort)

    this.bus.addListener("error", onErr)
    this.bus.addListener("data", onData)
    this.bus.addListener("end", onEnd)

    if (ac.signal.aborted) {
      started("")
      close(ac.signal.reason as Error)
      return it
    }

    let err: Error | undefined

    const fr = await fn()
    if (fr.err) {
      err = new Error("Calling operation", {cause: fr.err})
    } else {
      const [fd] = fr.v
      if (fd.id) {
        fid = fd.id
      } else {
        err = new Error("Operation ID is missing")
      }
    }

    started(fid)

    if (err) {
      close(err)
    }

    return it
  }

  private async terminate(id: string): Promise<r.Result<[FileOperationDto[], core.Response], Error>> {
    // The signal of the request may have aborted by now, so the termination
    // follows a signal of its own.
    const ex = (res: (v: r.Result<[FileOperationDto[], core.Response], Error>) => void): void => {
      const cb = (): void => {
        void this.client.files.terminateOperation(id).then(res)
      }

      context.run({[abort.signalKey]: AbortSignal.timeout(terminateTimeout)}, cb)
    }

    return await new Promise(ex)
  }
}
