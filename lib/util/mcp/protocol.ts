/**
 * @module
 * @mergeModuleWith util/mcp
 */

import * as helpers from "@modelcontextprotocol/sdk/experimental/tasks/helpers.js"
import type * as zodCompat from "@modelcontextprotocol/sdk/server/zod-compat.js"
import * as protocol from "@modelcontextprotocol/sdk/shared/protocol.js"
import type {Transport} from "@modelcontextprotocol/sdk/shared/transport.js"
import * as types from "@modelcontextprotocol/sdk/types.js"
import * as abort from "../abort.ts"
import * as context from "../context.ts"
import * as r from "../result.ts"
import {progressTokenKey, requestIdKey, taskIdKey} from "./context.ts"
import type {Router} from "./router.ts"

export class Protocol extends protocol.Protocol<types.Request, types.Notification, types.Result> {
	// The Protocol class from the SDK performs operations in its constructor that
	// involve abstract methods defined by our class. In these methods, we must
	// return early to allow the Protocol to complete its operations without
	// throwing an error. Therefore, the initialized field is not purely a boolean
	// type but can also be undefined. This happens because when the abstract
	// methods are called, our class constructor has not yet completed, so the
	// field is not yet defined — but we are already accessing it. This design
	// decision is dictated by the Protocol class from the SDK.
	private initialized: boolean | undefined = true

	private clientCapabilities: types.ClientCapabilities = {}
	private clientCapabilitiesLocked = false

	private serverCapabilities: types.ServerCapabilities = {}
	private serverCapabilitiesLocked = false

	getClientCapabilities(): types.ClientCapabilities {
		// Conceptually, it would be better to return a structured clone of the
		// capabilities, but we have to access them for every user request, which
		// makes cloning questionable.
		return this.clientCapabilities
	}

	getServerCapabilities(): types.ServerCapabilities {
		// Conceptually, it would be better to return a structured clone of the
		// capabilities, but we have to access them for every user request, which
		// makes cloning questionable.
		return this.serverCapabilities
	}

	lockClientCapabilities(): void {
		this.clientCapabilitiesLocked = true
	}

	lockServerCapabilities(): void {
		this.serverCapabilitiesLocked = true
	}

	registerClientCapabilities(cc: types.ClientCapabilities): void {
		if (this.clientCapabilitiesLocked) {
			throw new Error("Client capabilities are locked")
		}
		this.clientCapabilities = protocol.mergeCapabilities(this.clientCapabilities, cc)
	}

	registerServerCapabilities(sc: types.ServerCapabilities): void {
		if (this.serverCapabilitiesLocked) {
			throw new Error("Server capabilities are locked")
		}
		this.serverCapabilities = protocol.mergeCapabilities(this.serverCapabilities, sc)
	}

	registerRouter(router: Router): r.Result<void, Error> {
		let errs: Error[] = []

		let im = "initialize" as const
		let ih = router.handlers[im]
		if (ih) {
			let a = r.safeSync(this.assertCanSetRequestHandler.bind(this, im))
			if (a.err) {
				errs.push(new Error("Setting initialize handler", {cause: a.err}))
			}
		}

		let lsm = "logging/setLevel" as const
		let lsh = router.handlers[lsm]
		if (lsh) {
			let a = r.safeSync(this.assertCanSetRequestHandler.bind(this, lsm))
			if (a.err) {
				errs.push(new Error("Setting logging/setLevel handler", {cause: a.err}))
			}
		}

		let tcm = "tools/call" as const
		let tch = router.handlers[tcm]
		if (tch) {
			let a = r.safeSync(this.assertCanSetRequestHandler.bind(this, tcm))
			if (a.err) {
				errs.push(new Error("Setting tools/call handler", {cause: a.err}))
			}
		}

		let tlm = "tools/list" as const
		let tlh = router.handlers[tlm]
		if (tlh) {
			let a = r.safeSync(this.assertCanSetRequestHandler.bind(this, tlm))
			if (a.err) {
				errs.push(new Error("Setting tools/list handler", {cause: a.err}))
			}
		}

		if (errs.length !== 0) {
			return r.error(new AggregateError(errs, "Setting handlers"))
		}

		this.registerServerCapabilities(router.capabilities)

		if (ih) {
			this.setRequestHandler(types.InitializeRequestSchema, ih)
		}

		if (lsh) {
			this.setRequestHandler(types.SetLevelRequestSchema, lsh)
		}

		if (tch) {
			this.setRequestHandler(types.CallToolRequestSchema, tch)
		}

		if (tlh) {
			this.setRequestHandler(types.ListToolsRequestSchema, tlh)
		}

		return r.ok()
	}

	override async connect(transport: Transport): Promise<void> {
		this.lockServerCapabilities()
		await super.connect(transport)
	}

	override setRequestHandler<T extends zodCompat.AnyObjectSchema>(requestSchema: T, handler: (request: zodCompat.SchemaOutput<T>, extra: protocol.RequestHandlerExtra<types.Request, types.Notification>) => Promise<types.Result> | types.Result): void {
		handler = abort.wrapMcpHandler(handler)

		handler = ((handler) => {
			return async(req, extra) => {
				let ctx: context.Context = {}

				/* eslint-disable no-underscore-dangle */

				if (extra._meta && extra._meta.progressToken !== undefined) {
					ctx[progressTokenKey] = extra._meta.progressToken
				}

				ctx[requestIdKey] = extra.requestId

				if (extra.taskId) {
					ctx[taskIdKey] = extra.taskId
				}

				/* eslint-enable no-underscore-dangle */

				let ex = (res: (v: Awaited<ReturnType<typeof handler>>) => void, rej: (err: unknown) => void): void => {
					let cb = (): void => {
						void (async() => {
							try {
								res(await handler(req, extra))
							} catch (err) {
								rej(err)
							}
						})()
					}

					context.run(ctx, cb)
				}

				return await new Promise(ex)
			}
		})(handler)

		super.setRequestHandler(requestSchema, handler)
	}

	// Direct copy of https://github.com/modelcontextprotocol/typescript-sdk/blob/v1.27.1/src/server/index.ts#L296
	protected assertCapabilityForMethod(method: string): void {
		switch (method) {
		case "sampling/createMessage":
			if (!this.clientCapabilities.sampling) {
				throw new Error(`Client does not support sampling (required for ${method})`)
			}
			break

		case "elicitation/create":
			if (!this.clientCapabilities.elicitation) {
				throw new Error(`Client does not support elicitation (required for ${method})`)
			}
			break

		case "roots/list":
			if (!this.clientCapabilities.roots) {
				throw new Error(`Client does not support listing roots (required for ${method})`)
			}
			break

		case "ping":
			// No specific capability required for ping.
			break
		}
	}

	// Direct copy of https://github.com/modelcontextprotocol/typescript-sdk/blob/v1.27.1/src/server/index.ts#L322
	protected assertNotificationCapability(method: string): void {
		switch (method) {
		case "notifications/message":
			if (!this.serverCapabilities.logging) {
				throw new Error(`Server does not support logging (required for ${method})`)
			}
			break

		case "notifications/resources/updated":
		case "notifications/resources/list_changed":
			if (!this.serverCapabilities.resources) {
				throw new Error(`Server does not support notifying about resources (required for ${method})`)
			}
			break

		case "notifications/tools/list_changed":
			if (!this.serverCapabilities.tools) {
				throw new Error(`Server does not support notifying of tool list changes (required for ${method})`)
			}
			break

		case "notifications/prompts/list_changed":
			if (!this.serverCapabilities.prompts) {
				throw new Error(`Server does not support notifying of prompt list changes (required for ${method})`)
			}
			break

		case "notifications/elicitation/complete":
			if (!this.clientCapabilities.elicitation || !this.clientCapabilities.elicitation.url) {
				throw new Error(`Client does not support URL elicitation (required for ${method})`)
			}
			break

		case "notifications/cancelled":
			// Cancellation notifications are always allowed.
			break

		case "notifications/progress":
			// Progress notifications are always allowed.
			break
		}
	}

	// Direct copy of https://github.com/modelcontextprotocol/typescript-sdk/blob/v1.27.1/src/server/index.ts#L365
	protected assertRequestHandlerCapability(method: string): void {
		// Task handlers are registered in Protocol constructor before this class is
		// initialized. Skip compatibility check for task method during
		// initialization.
		if (!this.initialized) {
			return
		}

		switch (method) {
		case "completion/complete":
			if (!this.serverCapabilities.completions) {
				throw new Error(`Server does not support completions (required for ${method})`)
			}
			break

		case "logging/setLevel":
			if (!this.serverCapabilities.logging) {
				throw new Error(`Server does not support logging (required for ${method})`)
			}
			break

		case "prompts/get":
		case "prompts/list":
			if (!this.serverCapabilities.prompts) {
				throw new Error(`Server does not support prompts (required for ${method})`)
			}
			break

		case "resources/list":
		case "resources/templates/list":
		case "resources/read":
			if (!this.serverCapabilities.resources) {
				throw new Error(`Server does not support resources (required for ${method})`)
			}
			break

		case "tools/call":
		case "tools/list":
			if (!this.serverCapabilities.tools) {
				throw new Error(`Server does not support tools (required for ${method})`)
			}
			break

		case "tasks/get":
		case "tasks/list":
		case "tasks/result":
		case "tasks/cancel":
			if (!this.serverCapabilities.tasks) {
				throw new Error(`Server does not support tasks capability (required for ${method})`)
			}
			break

		case "ping":
		case "initialize":
			// No specific capability required for these methods.
			break
		}
	}

	// Direct copy of https://github.com/modelcontextprotocol/typescript-sdk/blob/v1.27.1/src/server/index.ts#L423
	protected assertTaskCapability(method: string): void {
		let c: Parameters<typeof helpers.assertClientRequestTaskCapability>[0]

		if (this.clientCapabilities.tasks) {
			c = this.clientCapabilities.tasks.requests
		}

		helpers.assertClientRequestTaskCapability(c, method, "Client")
	}

	// Direct copy of https://github.com/modelcontextprotocol/typescript-sdk/blob/v1.27.1/src/server/index.ts#L427
	protected assertTaskHandlerCapability(method: string): void {
		// Task handlers are registered in Protocol constructor before this class is
		// initialized. Skip compatibility check for task method during
		// initialization.
		if (!this.initialized) {
			return
		}

		let c: Parameters<typeof helpers.assertClientRequestTaskCapability>[0]

		if (this.serverCapabilities.tasks) {
			c = this.serverCapabilities.tasks.requests
		}

		helpers.assertToolsCallTaskCapability(c, method, "Server")
	}
}
