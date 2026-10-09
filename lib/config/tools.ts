/**
 * @module
 * @mergeModuleWith config
 * @hidden
 */

import * as mcp from "../mcp.ts"

export const availableToolsets: string[] = (() => {
  const a: string[] = ["all"]
  for (const s of mcp.regularToolsets) {
    a.push(s.name)
  }
  return a
})()

export const availableTools: string[] = (() => {
  const a: string[] = []
  for (const s of mcp.regularToolsets) {
    for (const t of s.tools) {
      a.push(t.name)
    }
  }
  return a
})()

export type ResolveToolsOptions = {
  toolsets: string[]
  enabledTools: string[]
  disabledTools: string[]
}

export type ResolveToolsResult = {
  toolsets: string[]
  tools: string[]
}

// todo: the behavior of this function is unclear
export function resolveTools(o: ResolveToolsOptions): ResolveToolsResult {
  let t = o.toolsets

  const i = t.indexOf("all")
  if (i !== -1) {
    t = availableToolsets
  }

  const x: string[] = []
  const y: string[] = []

  for (const n of t) {
    x.push(n)

    for (const s of mcp.regularToolsets) {
      if (s.name === n) {
        for (const t of s.tools) {
          y.push(t.name)
        }
        break
      }
    }
  }

  for (const n of o.enabledTools) {
    for (const s of mcp.regularToolsets) {
      let h = false
      for (const t of s.tools) {
        if (t.name === n) {
          h = true
          break
        }
      }

      if (h) {
        if (!x.includes(s.name)) {
          x.push(s.name)
        }
        break
      }
    }

    if (!y.includes(n)) {
      y.push(n)
    }
  }

  for (const n of o.disabledTools) {
    const i = y.indexOf(n)
    if (i !== -1) {
      y.splice(i, 1)
    }
  }

  for (const sn of x) {
    for (const s of mcp.regularToolsets) {
      if (s.name === sn) {
        let h = false

        for (const tn of y) {
          for (const t of s.tools) {
            if (t.name === tn) {
              h = true
              break
            }
          }

          if (h) {
            break
          }
        }

        if (!h) {
          const i = x.indexOf(sn)
          if (i !== -1) {
            x.splice(i, 1)
          }
        }

        break
      }
    }
  }

  const r: ResolveToolsResult = {
    toolsets: x,
    tools: y,
  }

  return r
}
