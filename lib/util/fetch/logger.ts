/**
 * @module
 * @mergeModuleWith util/fetch
 */

const outgoing = "<--"
const incoming = "-->"
const error = "xxx"

type Payload = {
	method?: string
	url?: string
	status?: number
	duration?: string
	err?: unknown
}

export type Logger = {
	info(m: string, o?: object): void | Promise<void>
	warn(m: string, o?: object): void | Promise<void>
	error(m: string, o?: object): void | Promise<void>
}

export function withLogger(l: Logger, fetch: typeof globalThis.fetch): typeof globalThis.fetch {
	return async(input, init) => {
		if (!(input instanceof Request)) {
			throw new Error("Input is not a Request instance")
		}

		let o: Payload = {
			method: input.method,
			url: input.url,
		}

		try {
			await l.info(incoming, o)

			let now = Date.now()

			let r = await fetch(input, init)

			o.status = r.status

			let d = Date.now() - now
			if (d < 1000) {
				o.duration = `${d}ms`
			} else {
				o.duration = `${Math.round(d / 1000)}s`
			}

			await l.info(outgoing, o)

			return r
		} catch (err) {
			o.err = err

			await l.error(error, o)

			throw err
		}
	}
}
