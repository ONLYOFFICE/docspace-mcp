/**
 * @module
 * @mergeModuleWith util/mcp
 */

import type * as protocol from "@modelcontextprotocol/sdk/shared/protocol.js"
import type * as types from "@modelcontextprotocol/sdk/types.js"

export type RequestHandlerMap = {
	"elicitation/create": ElicitRequestHandler
	"initialize": InitializeRequestHandler
	"logging/setLevel": SetLevelRequestHandler
	"tools/call": CallToolRequestHandler
	"tools/list": ListToolsRequestHandler
}

export type ElicitRequestHandler = RequestHandler<types.ElicitRequest, types.ElicitResult>

export type InitializeRequestHandler = RequestHandler<types.InitializeRequest, types.InitializeResult>

export type SetLevelRequestHandler = RequestHandler<types.SetLevelRequest>

export type CallToolRequestHandler = RequestHandler<types.CallToolRequest, types.CallToolResult>

export type ListToolsRequestHandler = RequestHandler<types.ListToolsRequest, types.ListToolsResult>

export type RequestHandler<Request extends types.Request = types.Request, Result extends types.Result = types.Result> = (this: void, request: Request, extra: protocol.RequestHandlerExtra<Request, types.Notification>) => Promise<Result> | Result
