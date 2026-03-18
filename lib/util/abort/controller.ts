/**
 * @module
 * @mergeModuleWith util/abort
 */

export class Controller {
	private ac = new AbortController()
	private ca: (() => void)[] = []

	get controller(): AbortController {
		return this.ac
	}

	get signal(): AbortSignal {
		return this.ac.signal
	}

	// eslint-disable-next-line typescript/explicit-module-boundary-types, typescript/no-explicit-any
	abort(reason?: any): void {
		this.ac.abort(reason)
	}

	clear(): void {
		for (let c of this.ca) {
			c()
		}
	}

	withSignal(s: AbortSignal): void {
		let l = (): void => {
			this.ac.abort(s.reason)
		}

		s.addEventListener("abort", l)

		let c = (): void => {
			s.removeEventListener("abort", l)
		}

		this.ca.push(c)
	}

	withTimeout(t: number): void {
		let f = (): void => {
			this.ac.abort(new DOMException("Timeout exceeded", "AbortError"))
		}

		let s = setTimeout(f, t)

		let c = (): void => {
			clearTimeout(s)
		}

		this.ca.push(c)
	}
}
