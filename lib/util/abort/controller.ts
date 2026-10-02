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

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  abort(reason?: any): void {
    this.ac.abort(reason)
  }

  clear(): void {
    for (const c of this.ca) {
      c()
    }
  }

  withSignal(s: AbortSignal): void {
    const l = (): void => {
      this.ac.abort(s.reason)
    }

    s.addEventListener("abort", l)

    const c = (): void => {
      s.removeEventListener("abort", l)
    }

    this.ca.push(c)
  }

  withTimeout(t: number): void {
    const f = (): void => {
      this.ac.abort(new DOMException("Timeout exceeded", "AbortError"))
    }

    const s = setTimeout(f, t)

    const c = (): void => {
      clearTimeout(s)
    }

    this.ca.push(c)
  }
}
