/**
 * @module
 * @mergeModuleWith api/extra
 */

import type events from "node:events"
import timers from "node:timers"
import type * as z from "zod"
import * as abort from "../../util/abort.ts"
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
		let [e] = p

		if (this.controller.signal.aborted && e === "data") {
			let c = new AbortController()

			let t: NodeJS.Timeout | undefined

			let onAbort = (): void => {
				clearTimeout(t)

				c.signal.removeEventListener("abort", onAbort)
			}

			let onTick = (): void => {
				void (async() => {
					await this.poll()

					if (!c.signal.aborted) {
						t = timers.setTimeout(onTick, this.interval)
					}
				})()
			}

			c.signal.addEventListener("abort", onAbort)

			t = timers.setTimeout(onTick, this.interval)

			this.controller = c
		}
	}

	private handleRemoveListener(): void {
		if (!this.controller.signal.aborted && this.bus.listenerCount("data") === 0) {
			this.controller.abort(new DOMException("No data listeners", "AbortError"))
		}
	}

	private async poll(): Promise<void> {
		let g = await this.client.files.getOperationStatuses()
		if (g.err) {
			this.bus.emit("error", "", new Error("Getting operation statuses", {cause: g.err}))
			return
		}

		let [d] = g.v

		for (let e of d) {
			if (!e.id) {
				continue
			}

			let errs: Error[] = []

			if (e.error) {
				errs.push(new Error(e.error))
			}

			if (e.status && e.status === 2 && e.processed && e.processed === "0") {
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
}

export class FileOperationCaller {
	private timeout: number
	private bus: FileOperationBus

	constructor(config: FileOperationCallerConfig) {
		this.timeout = config.timeout
		this.bus = config.bus
	}

	async call(fn: FileOperationFn): Promise<FileOperationIter> {
		let fid = ""
		let closed = false
		let buf: FileOperationDto[] = []
		let wake = (): void => {}
		let re = r.ok() as unknown as r.Result<FileOperationDto, Error>

		let it: FileOperationIter = {
			[Symbol.asyncIterator]() {
				return it
			},

			async next() {
				if (!closed && buf.length === 0) {
					let e = (res: () => void): void => {
						wake = res
					}

					await new Promise<void>(e)
				}

				let ir: IteratorResult<FileOperationDto, undefined> | undefined

				let v = buf.shift()

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

			// eslint-disable-next-line typescript/require-await
			async return() {
				close()

				let ir: IteratorResult<unknown, unknown> = {
					done: true,
					value: undefined,
				}

				return ir
			},

			result() {
				return {...re}
			},
		}

		let ac = new abort.Controller()

		if (this.timeout) {
			ac.withTimeout(this.timeout)
		}

		let onAbort = (): void => {
			close(ac.signal.reason)
		}

		let onErr = (id: string, err: Error): void => {
			if (fid && id === fid || !id) {
				close(err)
			}
		}

		let onData = (id: string, data: FileOperationDto): void => {
			if (fid && id === fid) {
				buf.push(data)
				re.v = data
				wake()
			}
		}

		let onEnd = (id: string): void => {
			if (fid && id === fid) {
				close()
			}
		}

		let close = (err?: Error): void => {
			if (closed) {
				return
			}

			if (err) {
				re.err = err
			}

			ac.signal.removeEventListener("abort", onAbort)

			this.bus.removeListener("error", onErr)
			this.bus.removeListener("data", onData)
			this.bus.removeListener("end", onEnd)

			ac.clear()

			closed = true

			wake()
		}

		ac.signal.addEventListener("abort", onAbort)

		this.bus.addListener("error", onErr)
		this.bus.addListener("data", onData)
		this.bus.addListener("end", onEnd)

		let err: Error | undefined

		let fr = await fn()
		if (fr.err) {
			err = new Error("Calling operation", {cause: fr.err})
		} else {
			let [fd] = fr.v
			if (fd.id) {
				fid = fd.id
			} else {
				err = new Error("Operation ID is missing")
			}
		}

		if (err) {
			close(err)
		}

		return it
	}
}
