/**
 * @module
 * @mergeModuleWith util/mcp
 */

import * as types from "@modelcontextprotocol/sdk/types.js"
import type {Router} from "./router.ts"

export type ServerProtocol = {
	getServerCapabilities(): types.ServerCapabilities
	lockClientCapabilities(): void
	registerClientCapabilities(cc: types.ClientCapabilities): void
}

export class Server {
	private protocol: ServerProtocol
	private implementation: types.Implementation

	constructor(protocol: ServerProtocol, implementation: types.Implementation) {
		this.protocol = protocol
		this.implementation = implementation
	}

	router(): Router {
		return {
			capabilities: {},
			handlers: {
				initialize: this.handleInitialize.bind(this),
			},
		}
	}

	private handleInitialize(req: types.InitializeRequest): types.InitializeResult {
		this.protocol.registerClientCapabilities(req.params.capabilities)
		this.protocol.lockClientCapabilities()

		let ir: types.InitializeResult = {
			protocolVersion: "",
			capabilities: this.protocol.getServerCapabilities(),
			serverInfo: this.implementation,
		}

		if (types.SUPPORTED_PROTOCOL_VERSIONS.includes(req.params.protocolVersion)) {
			ir.protocolVersion = req.params.protocolVersion
		} else {
			ir.protocolVersion = types.LATEST_PROTOCOL_VERSION
		}

		return ir
	}
}
