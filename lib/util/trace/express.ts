/**
 * @module
 * @mergeModuleWith util/trace
 */

import crypto from "node:crypto"
import type express from "express"
import * as context from "../context.ts"
import * as http from "../http.ts"
import {requestIdKey} from "./context.ts"

export function expressHandler(): express.Handler {
	return (req, res, next) => {
		let id = http.header(req, "X-Request-ID")

		if (!id) {
			id = crypto.randomUUID()
		}

		res.setHeader("X-Request-ID", id)

		let ctx: context.Context = {
			[requestIdKey]: id,
		}

		context.run(ctx, next)
	}
}
