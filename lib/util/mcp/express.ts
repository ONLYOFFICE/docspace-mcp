/**
 * @module
 * @mergeModuleWith util/mcp
 */

import type express from "express"
import * as context from "../context.ts"
import * as http from "../http.ts"
import {sessionIdKey} from "./context.ts"

export function expressHandler(): express.Handler {
  return (req, _, next) => {
    const id = http.header(req, "Mcp-Session-Id")

    if (id) {
      const ctx: context.Context = {
        [sessionIdKey]: id,
      }

      context.run(ctx, next)
      return
    }

    next()
  }
}
