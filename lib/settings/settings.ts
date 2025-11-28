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

/**
 * @module
 * @mergeModuleWith settings
 */

/* eslint-disable typescript/consistent-type-definitions */

import type express from "express"
import * as z from "zod"
import * as errors from "../util/errors.ts"
import * as r from "../util/result.ts"
import * as zod from "../util/zod.ts"
import type {ResolveToolsOptions} from "./tools.ts"
import {resolveTools} from "./tools.ts"

export type Settings = {
	dynamic: boolean
	toolsets: string[]
	tools: string[]
}

type SettingsQuery = z.infer<Exclude<SettingsParser["querySchema"], undefined>>

type SettingsHeader = z.infer<Exclude<SettingsParser["headerSchema"], undefined>>

export type SettingsParserConfig = {
	defaultDynamic: boolean
	defaultToolsets: string[]
	defaultTools: string[]
	queryEnabled: boolean
	headerPrefix: string
}

export class SettingsParser {
	private defaultDynamic: boolean
	private defaultToolsets: string[]
	private defaultTools: string[]

	requestHeaders: string[]

	private querySchema
	private headerSchema

	constructor(config: SettingsParserConfig) {
		this.defaultDynamic = config.defaultDynamic
		this.defaultToolsets = config.defaultToolsets
		this.defaultTools = config.defaultTools

		this.requestHeaders = []

		if (config.queryEnabled) {
			this.querySchema = z.
				object({
					dynamic: z.string().optional().transform(zod.envOptionalBoolean()),
					toolsets: z.string().optional().transform(zod.envOptionalOptions([])),
					enabled_tools: z.string().optional().transform(zod.envOptionalOptions([])),
					disabled_tools: z.string().optional().transform(zod.envOptionalOptions([])),
				}).
				transform((o) => ({
					dynamic: o.dynamic,
					toolsets: o.toolsets,
					enabledTools: o.enabled_tools,
					disabledTools: o.disabled_tools,
				}))
		}

		if (config.headerPrefix) {
			let dynamic = `${config.headerPrefix}dynamic`
			let toolsets = `${config.headerPrefix}toolsets`
			let enabledTools = `${config.headerPrefix}enabled-tools`
			let disabledTools = `${config.headerPrefix}disabled-tools`

			this.requestHeaders.push(
				dynamic,
				toolsets,
				enabledTools,
				disabledTools,
			)

			this.headerSchema = z.
				object({
					[dynamic]: z.string().optional().transform(zod.envOptionalBoolean()),
					[toolsets]: z.string().optional().transform(zod.envOptionalOptions(config.defaultToolsets)), // eslint-disable-line stylistic/max-len
					[enabledTools]: z.string().optional().transform(zod.envOptionalOptions(config.defaultTools)), // eslint-disable-line stylistic/max-len
					[disabledTools]: z.string().optional().transform(zod.envOptionalOptions(config.defaultTools)), // eslint-disable-line stylistic/max-len
				}).
				transform((o) => ({
					dynamic: o[dynamic] as boolean | undefined,
					toolsets: o[toolsets] as string[] | undefined,
					enabledTools: o[enabledTools] as string[] | undefined,
					disabledTools: o[disabledTools] as string[] | undefined,
				}))
		}
	}

	parse(req: express.Request): r.Result<Settings, Error> {
		let q: SettingsQuery | undefined

		if (this.querySchema) {
			let p = this.querySchema.safeParse(req.query)
			if (!p.success) {
				return r.error(new Error("Parsing query", {cause: p.error}))
			}
			q = p.data
		}

		let h: SettingsHeader | undefined

		if (this.headerSchema) {
			let p = this.headerSchema.safeParse(req.headers)
			if (!p.success) {
				return r.error(new Error("Parsing header", {cause: p.error}))
			}
			h = p.data
		}

		let errs: Error[] = []

		// todo: do not register errors if value in query and in header are equal

		if (q && q.dynamic !== undefined && h && h.dynamic !== undefined) {
			errs.push(new Error("Both query and header specify dynamic"))
		}

		if (q && q.toolsets !== undefined && h && h.toolsets !== undefined) {
			errs.push(new Error("Both query and header specify toolsets"))
		}

		if (q && q.enabledTools !== undefined && h && h.enabledTools !== undefined) {
			errs.push(new Error("Both query and header specify enabled tools"))
		}

		if (q && q.disabledTools !== undefined && h && h.disabledTools !== undefined) {
			errs.push(new Error("Both query and header specify disabled tools"))
		}

		if (errs.length !== 0) {
			return r.error(new errors.Errors({cause: errs}))
		}

		let dynamic: boolean | undefined

		if (q && q.dynamic !== undefined) {
			dynamic = q.dynamic
		} else if (h && h.dynamic !== undefined) {
			dynamic = h.dynamic
		} else {
			dynamic = this.defaultDynamic
		}

		let o: ResolveToolsOptions = {
			toolsets: [],
			enabledTools: [],
			disabledTools: [],
		}

		if (q && q.toolsets !== undefined) {
			o.toolsets = q.toolsets
		} else if (h && h.toolsets !== undefined) {
			o.toolsets = h.toolsets
		} else {
			o.toolsets = this.defaultToolsets
		}

		if (q && q.enabledTools !== undefined) {
			o.enabledTools = q.enabledTools
		} else if (h && h.enabledTools !== undefined) {
			o.enabledTools = h.enabledTools
		} else {
			o.enabledTools = this.defaultTools
		}

		if (q && q.disabledTools !== undefined) {
			o.disabledTools = q.disabledTools
		} else if (h && h.disabledTools !== undefined) {
			o.disabledTools = h.disabledTools
		} else {
			o.disabledTools = []
		}

		let t = resolveTools(o)

		if (t.toolsets.length === 0) {
			errs.push(new Error("No toolsets left"))
		}

		if (t.tools.length === 0) {
			errs.push(new Error("No tools left"))
		}

		if (errs.length !== 0) {
			return r.error(new errors.Errors({cause: errs}))
		}

		let s: Settings = {
			dynamic,
			toolsets: t.toolsets,
			tools: t.tools,
		}

		return r.ok(s)
	}
}
