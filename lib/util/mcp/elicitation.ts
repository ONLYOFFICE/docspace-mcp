/**
 * @module
 * @mergeModuleWith util/mcp
 */

import type * as zodCompat from "@modelcontextprotocol/sdk/server/zod-compat.js"
import type * as protocol from "@modelcontextprotocol/sdk/shared/protocol.js"
import * as types from "@modelcontextprotocol/sdk/types.js"
import type * as z from "zod"
import * as abort from "../abort.ts"
import * as context from "../context.ts"
import * as r from "../result.ts"
import {requestIdKey, taskIdKey} from "./context.ts"

export const ElicitationFormRequestedSchemaSchema = types.ElicitRequestFormParamsSchema.def.shape.requestedSchema

export type ElicitationFormRequestedSchema = z.infer<typeof ElicitationFormRequestedSchemaSchema>

export type ElicitationProtocol = {
	getClientCapabilities(): types.ClientCapabilities
	request<T extends zodCompat.AnySchema>(request: types.Request, resultSchema: T, options?: protocol.RequestOptions): Promise<zodCompat.SchemaOutput<T>>
}

export class Elicitation {
	private protocol: ElicitationProtocol

	constructor(protocol: ElicitationProtocol) {
		this.protocol = protocol
	}

	async form(m: string, s: ElicitationFormRequestedSchema): Promise<r.Result<types.ElicitResult, Error>> {
		let ctx = context.get()

		let cc = this.protocol.getClientCapabilities()

		if (!cc.elicitation || !cc.elicitation.form) {
			return r.error(new Error("Client does not support form elicitation"))
		}

		let er: types.ElicitRequest = {
			method: "elicitation/create",
			params: {
				mode: "form",
				message: m,
				requestedSchema: s,
			},
		}

		let ro: protocol.RequestOptions = {}

		if (ctx[abort.signalKey]) {
			ro.signal = ctx[abort.signalKey]
		}

		if (ctx[requestIdKey]) {
			ro.relatedRequestId = ctx[requestIdKey]
		}

		if (ctx[taskIdKey]) {
			ro.relatedTask = {taskId: ctx[taskIdKey]}
		}

		let rw = await r.safeAsync(
			this.protocol.request.bind(this.protocol),
			er,
			types.ElicitResultSchema,
			ro,
		)
		if (rw.err) {
			return r.error(new Error("Making request", {cause: rw.err}))
		}

		return r.ok(rw.v)
	}
}
