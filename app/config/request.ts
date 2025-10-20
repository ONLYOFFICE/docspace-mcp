/**
 * (c) Copyright Ascensio System SIA 2025
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @license
 */

import type * as express from "express"
import * as z from "zod"
import * as errors from "../../lib/util/errors.ts"
import * as result from "../../lib/util/result.ts"
import * as zod from "../../lib/util/zod.ts"
import type * as global from "./global.ts"
import * as tools from "./tools.ts"

export interface Mcp {
	dynamic: boolean
	toolsets: string[]
	tools: string[]
	enabledTools: string[]
	disabledTools: string[]
}

export interface ApiShared {
	baseUrl: string
	authorization: string
	apiKey: string
	pat: string
	username: string
	password: string
}

const QueryMcpSchema = z.
	object({
		dynamic: z.
			string().
			optional().
			transform(zod.envOptionalBoolean()),

		toolsets: z.
			string().
			optional().
			transform(zod.envOptionalOptions([])),

		enabled_tools: z.
			string().
			optional().
			transform(zod.envOptionalOptions([])),

		disabled_tools: z.
			string().
			optional().
			transform(zod.envOptionalOptions([])),
	}).
	transform((o) => ({
		dynamic: o.dynamic,
		toolsets: o.toolsets,
		enabledTools: o.enabled_tools,
		disabledTools: o.disabled_tools,
	}))

const QueryApiSharedSchema = z.
	object({
		base_url: z.
			string().
			optional().
			transform(zod.envOptionalBaseUrl()),
	}).
	transform((o) => ({
		baseUrl: o.base_url,
	}))

let HeaderMcpSchema: ReturnType<typeof createMcp> | undefined

let HeaderApiSharedSchema: ReturnType<typeof createApiShared> | undefined

export function setup(g: global.Config): void {
	if (g.request.headerPrefix) {
		HeaderMcpSchema = createMcp(g)
		HeaderApiSharedSchema = createApiShared(g)
	}
}

// eslint-disable-next-line typescript/explicit-function-return-type
function createMcp(g: global.Config) {
	let keyDynamic = `${g.request.headerPrefix}dynamic`
	let keyToolsets = `${g.request.headerPrefix}toolsets`
	let keyEnabledTools = `${g.request.headerPrefix}enabled-tools`
	let keyDisabledTools = `${g.request.headerPrefix}disabled-tools`

	return z.
		object({
			[keyDynamic]: z.
				string().
				optional().
				transform(zod.envOptionalBoolean()),

			[keyToolsets]: z.
				string().
				optional().
				transform(zod.envOptionalOptions([...g.mcp.toolsets])),

			[keyEnabledTools]: z.
				string().
				optional().
				transform(zod.envOptionalOptions([...g.mcp.tools])),

			[keyDisabledTools]: z.
				string().
				optional().
				transform(zod.envOptionalOptions([...g.mcp.tools])),
		}).
		transform((o) => ({
			dynamic: o[keyDynamic] as boolean | undefined,
			toolsets: o[keyToolsets] as string[] | undefined,
			enabledTools: o[keyEnabledTools] as string[] | undefined,
			disabledTools: o[keyDisabledTools] as string[] | undefined,
		}))
}

// eslint-disable-next-line typescript/explicit-function-return-type
function createApiShared(g: global.Config) {
	let keyBaseUrl = `${g.request.headerPrefix}base-url`
	let keyApiKey = `${g.request.headerPrefix}api-key`
	let keyAuthToken = `${g.request.headerPrefix}auth-token`
	let keyUsername = `${g.request.headerPrefix}username`
	let keyPassword = `${g.request.headerPrefix}password`

	return z.
		object({
			[keyBaseUrl]: z.
				string().
				optional().
				transform(zod.envOptionalBaseUrl()),

			[keyApiKey]: z.
				string().
				trim().
				optional(),

			[keyAuthToken]: z.
				string().
				trim().
				optional(),

			[keyUsername]: z.
				string().
				time().
				optional(),

			[keyPassword]: z.
				string().
				time().
				optional(),
		}).
		transform((o) => ({
			baseUrl: o[keyBaseUrl],
			apiKey: o[keyApiKey],
			pat: o[keyAuthToken],
			username: o[keyUsername],
			password: o[keyPassword],
		}))
}

export function parseMcp(g: global.Config, v: express.Request): result.Result<Mcp, Error> {
	let qd: z.infer<typeof QueryMcpSchema> | undefined

	if (g.request.query) {
		let p = QueryMcpSchema.safeParse(v.query)
		if (p.error) {
			return result.error(new Error("Parsing query", {cause: p.error}))
		}

		qd = p.data
	}

	let hd: z.infer<Exclude<typeof HeaderMcpSchema, undefined>> | undefined

	if (g.request.headerPrefix) {
		if (!HeaderMcpSchema) {
			return result.error(new Error("MCP schema was not initialized"))
		}

		let p = HeaderMcpSchema.safeParse(v.headers)
		if (p.error) {
			return result.error(new Error("Parsing headers", {cause: p.error}))
		}

		hd = p.data
	}

	let errs: Error[] = []

	if (qd && qd.dynamic !== undefined && hd && hd.dynamic !== undefined) {
		errs.push(new Error("Both query and header specify dynamic"))
	}

	if (qd && qd.toolsets !== undefined && hd && hd.toolsets !== undefined) {
		errs.push(new Error("Both query and header specify toolsets"))
	}

	if (qd && qd.enabledTools !== undefined && hd && hd.enabledTools !== undefined) {
		errs.push(new Error("Both query and header specify enabled tools"))
	}

	if (qd && qd.disabledTools !== undefined && hd && hd.disabledTools !== undefined) {
		errs.push(new Error("Both query and header specify disabled tools"))
	}

	if (errs.length !== 0) {
		return result.error(new errors.Errors({cause: errs}))
	}

	let pc: Mcp = {
		dynamic: false,
		toolsets: [],
		tools: [],
		enabledTools: [],
		disabledTools: [],
	}

	if (qd && qd.dynamic !== undefined) {
		pc.dynamic = qd.dynamic
	} else if (hd && hd.dynamic !== undefined) {
		pc.dynamic = hd.dynamic
	} else {
		pc.dynamic = g.mcp.dynamic
	}

	if (qd && qd.toolsets !== undefined) {
		pc.toolsets = qd.toolsets
	} else if (hd && hd.toolsets !== undefined) {
		pc.toolsets = hd.toolsets
	} else {
		pc.toolsets = [...g.mcp.toolsets]
	}

	if (qd && qd.enabledTools !== undefined) {
		pc.enabledTools = qd.enabledTools
	} else if (hd && hd.enabledTools !== undefined) {
		pc.enabledTools = hd.enabledTools
	} else {
		pc.enabledTools = [...g.mcp.enabledTools]
	}

	if (qd && qd.disabledTools !== undefined) {
		pc.disabledTools = qd.disabledTools
	} else if (hd && hd.disabledTools !== undefined) {
		pc.disabledTools = hd.disabledTools
	} else {
		pc.disabledTools = [...g.mcp.disabledTools]
	}

	pc.toolsets = tools.normalizeToolsets(pc.toolsets)

	;[pc.toolsets, pc.tools] = tools.resolveToolsetsAndTools(
		pc.toolsets,
		pc.enabledTools,
		pc.disabledTools,
	)

	if (pc.toolsets.length === 0) {
		errs.push(new Error("No toolsets left"))
	}

	if (pc.tools.length === 0) {
		errs.push(new Error("No tools left"))
	}

	if (errs.length !== 0) {
		return result.error(new errors.Errors({cause: errs}))
	}

	return result.ok(pc)
}

export function parseApiShared(g: global.Config, v: express.Request): result.Result<ApiShared, Error> {
	let qd: z.infer<typeof QueryApiSharedSchema> | undefined

	if (g.request.query) {
		let p = QueryApiSharedSchema.safeParse(v.query)
		if (p.error) {
			return result.error(new Error("Parsing query", {cause: p.error}))
		}

		qd = p.data
	}

	let au: string | undefined

	if (g.request.authorizationHeader) {
		au = v.headers.authorization
	}

	let hd: z.infer<Exclude<typeof HeaderApiSharedSchema, undefined>> | undefined

	if (g.request.headerPrefix) {
		if (!HeaderApiSharedSchema) {
			return result.error(new Error("API shared schema was not initialized"))
		}

		let p = HeaderApiSharedSchema.safeParse(v.headers)
		if (p.error) {
			return result.error(new Error("Parsing headers", {cause: p.error}))
		}

		hd = p.data
	}

	let errs: Error[] = []

	if (qd && qd.baseUrl !== undefined && hd && hd.baseUrl !== undefined) {
		errs.push(new Error("Both query and header specify base URL"))
	}

	if (errs.length !== 0) {
		return result.error(new errors.Errors({cause: errs}))
	}

	let pc: ApiShared = {
		baseUrl: "",
		authorization: "",
		apiKey: "",
		pat: "",
		username: "",
		password: "",
	}

	if (qd && qd.baseUrl !== undefined) {
		pc.baseUrl = qd.baseUrl
	} else if (hd && hd.baseUrl !== undefined) {
		pc.baseUrl = hd.baseUrl
	}

	if (au) {
		pc.authorization = au
	}

	if (hd && hd.apiKey !== undefined) {
		pc.apiKey = hd.apiKey
	}

	if (hd && hd.pat !== undefined) {
		pc.pat = hd.pat
	}

	if (hd && hd.username !== undefined) {
		pc.username = hd.username
	}

	if (hd && hd.password !== undefined) {
		pc.password = hd.password
	}

	if (
		(qd && qd.baseUrl === undefined || hd && hd.baseUrl === undefined) &&
		au === undefined &&
		(hd && hd.apiKey === undefined) &&
		(hd && hd.pat === undefined) &&
		(hd && hd.username === undefined) &&
		(hd && hd.password === undefined)
	) {
		pc.baseUrl = g.api.shared.baseUrl
		pc.authorization = g.api.shared.authorization
		pc.apiKey = g.api.shared.apiKey
		pc.pat = g.api.shared.pat
		pc.username = g.api.shared.username
		pc.password = g.api.shared.password
	}

	let ba = Boolean(pc.authorization)
	let bb = Boolean(pc.apiKey)
	let bc = Boolean(pc.pat)
	let bd = Boolean(pc.username) && Boolean(pc.password)
	let bu = Number(ba) + Number(bb) + Number(bc) + Number(bd)

	if (bu === 0) {
		errs.push(new Error("Expected at least one of Authorization header, API key, PAT, or (username and password) to be set"))
	}

	if (bu !== 0 && bu !== 1) {
		errs.push(new Error("Expected only one of Authorization header, API key, PAT, or (username and password) to be set"))
	}

	if ((ba || bb || bc || bd) && !pc.baseUrl) {
		errs.push(new Error("API base URL is required with Authorization header, API key, PAT, or (username and password)"))
	}

	if (errs.length !== 0) {
		return result.error(new errors.Errors({cause: errs}))
	}

	return result.ok(pc)
}
