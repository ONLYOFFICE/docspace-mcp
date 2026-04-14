/**
 * @module
 * @mergeModuleWith config
 */

import * as z from "zod"
import * as zod from "../util/zod.ts"
import * as spec from "./spec.ts"
import type {ResolveToolsOptions} from "./tools.ts"
import {availableTools, availableToolsets, resolveTools} from "./tools.ts"

export const envPrefix = "DOCSPACE_"

export type Env = z.infer<typeof EnvSchema>

export const EnvSchema = z.
	object({
		[`${envPrefix}INTERNAL`]: z.
			string().
			prefault("0").
			transform(zod.envBoolean()),
		[`${envPrefix}${spec.transport.env}`]: z.
			string().
			toLowerCase().
			prefault(prefault(spec.transport.default)).
			transform(zod.envUnion(spec.transport.choices)),
		[`${envPrefix}${spec.dynamic.env}`]: z.
			string().
			prefault(prefault(spec.dynamic.default)).
			transform(zod.envBoolean()),
		[`${envPrefix}${spec.toolsets.env}`]: z.
			string().
			prefault(prefault(spec.toolsets.default)).
			transform(zod.envOptions(availableToolsets)),
		[`${envPrefix}${spec.enabledTools.env}`]: z.
			string().
			prefault(prefault(spec.enabledTools.default)).
			transform(zod.envOptions(availableTools)),
		[`${envPrefix}${spec.disabledTools.env}`]: z.
			string().
			prefault(prefault(spec.disabledTools.default)).
			transform(zod.envOptions(availableTools)),
		[`${envPrefix}${spec.sessionTtl.env}`]: z.
			string().
			prefault(prefault(spec.sessionTtl.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.sessionInterval.env}`]: z.
			string().
			prefault(prefault(spec.sessionInterval.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.userAgent.env}`]: z.
			string().
			trim().
			prefault(prefault(spec.userAgent.default)),
		[`${envPrefix}${spec.baseUrl.env}`]: z.
			string().
			prefault(prefault(spec.baseUrl.default)).
			transform(zod.envBaseUrl()),
		[`${envPrefix}${spec.authorization.env}`]: z.
			string().
			trim().
			prefault(prefault(spec.authorization.default)),
		[`${envPrefix}${spec.apiKey.env}`]: z.
			string().
			trim().
			prefault(prefault(spec.apiKey.default)),
		[`${envPrefix}${spec.authToken.env}`]: z.
			string().
			trim().
			prefault(prefault(spec.authToken.default)),
		[`${envPrefix}${spec.username.env}`]: z.
			string().
			trim().
			prefault(prefault(spec.username.default)),
		[`${envPrefix}${spec.password.env}`]: z.
			string().
			trim().
			prefault(prefault(spec.password.default)),
		[`${envPrefix}${spec.oauthBaseUrl.env}`]: z.
			string().
			prefault(prefault(spec.oauthBaseUrl.default)).
			transform(zod.envBaseUrl()),
		[`${envPrefix}${spec.oauthClientId.env}`]: z.
			string().
			trim().
			prefault(prefault(spec.oauthClientId.default)),
		[`${envPrefix}${spec.oauthClientSecret.env}`]: z.
			string().
			trim().
			prefault(prefault(spec.oauthClientSecret.default)),
		[`${envPrefix}${spec.oauthAuthTokenAlgorithm.env}`]: z.
			string().
			toUpperCase().
			prefault(prefault(spec.oauthAuthTokenAlgorithm.default)).
			transform(zod.envUnion(["", ...spec.oauthAuthTokenAlgorithm.choices])),
		[`${envPrefix}${spec.oauthAuthTokenTtl.env}`]: z.
			string().
			prefault(prefault(spec.oauthAuthTokenTtl.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.oauthAuthTokenSecretKey.env}`]: z.
			string().
			trim().
			prefault(prefault(spec.oauthAuthTokenSecretKey.default)),
		[`${envPrefix}${spec.oauthStateTokenAlgorithm.env}`]: z.
			string().
			toUpperCase().
			prefault(prefault(spec.oauthStateTokenAlgorithm.default)).
			transform(zod.envUnion(["", ...spec.oauthStateTokenAlgorithm.choices])),
		[`${envPrefix}${spec.oauthStateTokenTtl.env}`]: z.
			string().
			prefault(prefault(spec.oauthStateTokenTtl.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.oauthStateTokenSecretKey.env}`]: z.
			string().
			trim().
			prefault(prefault(spec.oauthStateTokenSecretKey.default)),
		[`${envPrefix}${spec.fileOperationInterval.env}`]: z.
			string().
			prefault(prefault(spec.fileOperationInterval.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.fileOperationTimeout.env}`]: z.
			string().
			prefault(prefault(spec.fileOperationTimeout.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.serverBaseUrl.env}`]: z.
			string().
			prefault(prefault(spec.serverBaseUrl.default)).
			transform(zod.envBaseUrl()),
		[`${envPrefix}${spec.host.env}`]: z.
			string().
			trim().
			prefault(prefault(spec.host.default)),
		[`${envPrefix}${spec.port.env}`]: z.
			string().
			prefault(prefault(spec.port.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0).max(65535)),
		[`${envPrefix}${spec.proxyHops.env}`]: z.
			string().
			prefault(prefault(spec.proxyHops.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.serverAllowedHostnames.env}`]: z.
			string().
			prefault(prefault(spec.serverAllowedHostnames.default)).
			transform(zod.envHostnameList()),
		[`${envPrefix}${spec.serverCorsMcpOrigin.env}`]: z.
			string().
			prefault(prefault(spec.serverCorsMcpOrigin.default)).
			transform(zod.envList()),
		[`${envPrefix}${spec.serverCorsMcpMaxAge.env}`]: z.
			string().
			prefault(prefault(spec.serverCorsMcpMaxAge.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.serverCorsOauthOrigin.env}`]: z.
			string().
			prefault(prefault(spec.serverCorsOauthOrigin.default)).
			transform(zod.envList()),
		[`${envPrefix}${spec.serverCorsOauthMaxAge.env}`]: z.
			string().
			prefault(prefault(spec.serverCorsOauthMaxAge.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.serverRateLimitsMcpCapacity.env}`]: z.
			string().
			prefault(prefault(spec.serverRateLimitsMcpCapacity.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.serverRateLimitsMcpWindow.env}`]: z.
			string().
			prefault(prefault(spec.serverRateLimitsMcpWindow.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.serverRateLimitsOauthServerMetadataCapacity.env}`]: z.
			string().
			prefault(prefault(spec.serverRateLimitsOauthServerMetadataCapacity.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.serverRateLimitsOauthServerMetadataWindow.env}`]: z.
			string().
			prefault(prefault(spec.serverRateLimitsOauthServerMetadataWindow.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.serverRateLimitsOauthResourceMetadataCapacity.env}`]: z.
			string().
			prefault(prefault(spec.serverRateLimitsOauthResourceMetadataCapacity.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.serverRateLimitsOauthResourceMetadataWindow.env}`]: z.
			string().
			prefault(prefault(spec.serverRateLimitsOauthResourceMetadataWindow.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.serverRateLimitsOauthAuthorizeCapacity.env}`]: z.
			string().
			prefault(prefault(spec.serverRateLimitsOauthAuthorizeCapacity.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.serverRateLimitsOauthAuthorizeWindow.env}`]: z.
			string().
			prefault(prefault(spec.serverRateLimitsOauthAuthorizeWindow.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.serverRateLimitsOauthCallbackCapacity.env}`]: z.
			string().
			prefault(prefault(spec.serverRateLimitsOauthCallbackCapacity.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.serverRateLimitsOauthCallbackWindow.env}`]: z.
			string().
			prefault(prefault(spec.serverRateLimitsOauthCallbackWindow.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.serverRateLimitsOauthIntrospectCapacity.env}`]: z.
			string().
			prefault(prefault(spec.serverRateLimitsOauthIntrospectCapacity.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.serverRateLimitsOauthIntrospectWindow.env}`]: z.
			string().
			prefault(prefault(spec.serverRateLimitsOauthIntrospectWindow.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.serverRateLimitsOauthRegisterCapacity.env}`]: z.
			string().
			prefault(prefault(spec.serverRateLimitsOauthRegisterCapacity.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.serverRateLimitsOauthRegisterWindow.env}`]: z.
			string().
			prefault(prefault(spec.serverRateLimitsOauthRegisterWindow.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.serverRateLimitsOauthRevokeCapacity.env}`]: z.
			string().
			prefault(prefault(spec.serverRateLimitsOauthRevokeCapacity.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.serverRateLimitsOauthRevokeWindow.env}`]: z.
			string().
			prefault(prefault(spec.serverRateLimitsOauthRevokeWindow.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.serverRateLimitsOauthTokenCapacity.env}`]: z.
			string().
			prefault(prefault(spec.serverRateLimitsOauthTokenCapacity.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.serverRateLimitsOauthTokenWindow.env}`]: z.
			string().
			prefault(prefault(spec.serverRateLimitsOauthTokenWindow.default)).
			transform(zod.envNumber()).
			pipe(z.number().min(0)),
		[`${envPrefix}${spec.requestQuery.env}`]: z.
			string().
			prefault(prefault(spec.requestQuery.default)).
			transform(zod.envBoolean()),
		[`${envPrefix}${spec.requestAuthorizationHeader.env}`]: z.
			string().
			prefault(prefault(spec.requestAuthorizationHeader.default)).
			transform(zod.envBoolean()),
		[`${envPrefix}${spec.requestHeaderPrefix.env}`]: z.
			string().
			trim().
			toLowerCase().
			prefault(prefault(spec.requestHeaderPrefix.default)),
	}).
	transform((o) => ({
		internal: o[`${envPrefix}INTERNAL`] as boolean,
		mcp: {
			transport: o[`${envPrefix}${spec.transport.env}`] as spec.ItemTransportChoice,
			dynamic: o[`${envPrefix}${spec.dynamic.env}`] as boolean,
			toolsets: o[`${envPrefix}${spec.toolsets.env}`] as string[],
			tools: [] as string[],
			enabledTools: o[`${envPrefix}${spec.enabledTools.env}`] as string[],
			disabledTools: o[`${envPrefix}${spec.disabledTools.env}`] as string[],
			session: {
				ttl: o[`${envPrefix}${spec.sessionTtl.env}`] as number,
				interval: o[`${envPrefix}${spec.sessionInterval.env}`] as number,
			},
		},
		api: {
			userAgent: o[`${envPrefix}${spec.userAgent.env}`] as string,
			shared: {
				baseUrl: o[`${envPrefix}${spec.baseUrl.env}`] as string,
				authorization: o[`${envPrefix}${spec.authorization.env}`] as string,
				apiKey: o[`${envPrefix}${spec.apiKey.env}`] as string,
				pat: o[`${envPrefix}${spec.authToken.env}`] as string,
				username: o[`${envPrefix}${spec.username.env}`] as string,
				password: o[`${envPrefix}${spec.password.env}`] as string,
			},
			oauth: {
				baseUrl: o[`${envPrefix}${spec.oauthBaseUrl.env}`] as string,
				clientId: o[`${envPrefix}${spec.oauthClientId.env}`] as string,
				clientSecret: o[`${envPrefix}${spec.oauthClientSecret.env}`] as string,
			},
		},
		oauth: {
			authToken: {
				algorithm: o[`${envPrefix}${spec.oauthAuthTokenAlgorithm.env}`] as spec.ItemAlgorithmChoice | "",
				ttl: o[`${envPrefix}${spec.oauthAuthTokenTtl.env}`] as number,
				secretKey: o[`${envPrefix}${spec.oauthAuthTokenSecretKey.env}`] as string,
			},
			stateToken: {
				algorithm: o[`${envPrefix}${spec.oauthStateTokenAlgorithm.env}`] as spec.ItemAlgorithmChoice | "",
				ttl: o[`${envPrefix}${spec.oauthStateTokenTtl.env}`] as number,
				secretKey: o[`${envPrefix}${spec.oauthStateTokenSecretKey.env}`] as string,
			},
		},
		fileOperation: {
			interval: o[`${envPrefix}${spec.fileOperationInterval.env}`] as number,
			timeout: o[`${envPrefix}${spec.fileOperationTimeout.env}`] as number,
		},
		proxy: {
			hops: o[`${envPrefix}${spec.proxyHops.env}`] as number,
		},
		server: {
			baseUrl: o[`${envPrefix}${spec.serverBaseUrl.env}`] as string,
			host: o[`${envPrefix}${spec.host.env}`] as string,
			port: o[`${envPrefix}${spec.port.env}`] as number,
			allowedHostnames: o[`${envPrefix}${spec.serverAllowedHostnames.env}`] as string[],
			cors: {
				mcp: {
					origin: o[`${envPrefix}${spec.serverCorsMcpOrigin.env}`] as string[],
					maxAge: o[`${envPrefix}${spec.serverCorsMcpMaxAge.env}`] as number,
				},
				oauth: {
					origin: o[`${envPrefix}${spec.serverCorsOauthOrigin.env}`] as string[],
					maxAge: o[`${envPrefix}${spec.serverCorsOauthMaxAge.env}`] as number,
				},
			},
			rateLimits: {
				mcp: {
					capacity: o[`${envPrefix}${spec.serverRateLimitsMcpCapacity.env}`] as number,
					window: o[`${envPrefix}${spec.serverRateLimitsMcpWindow.env}`] as number,
				},
				oauth: {
					serverMetadata: {
						capacity: o[`${envPrefix}${spec.serverRateLimitsOauthServerMetadataCapacity.env}`] as number,
						window: o[`${envPrefix}${spec.serverRateLimitsOauthServerMetadataWindow.env}`] as number,
					},
					resourceMetadata: {
						capacity: o[`${envPrefix}${spec.serverRateLimitsOauthResourceMetadataCapacity.env}`] as number,
						window: o[`${envPrefix}${spec.serverRateLimitsOauthResourceMetadataWindow.env}`] as number,
					},
					authorize: {
						capacity: o[`${envPrefix}${spec.serverRateLimitsOauthAuthorizeCapacity.env}`] as number,
						window: o[`${envPrefix}${spec.serverRateLimitsOauthAuthorizeWindow.env}`] as number,
					},
					callback: {
						capacity: o[`${envPrefix}${spec.serverRateLimitsOauthCallbackCapacity.env}`] as number,
						window: o[`${envPrefix}${spec.serverRateLimitsOauthCallbackWindow.env}`] as number,
					},
					introspect: {
						capacity: o[`${envPrefix}${spec.serverRateLimitsOauthIntrospectCapacity.env}`] as number,
						window: o[`${envPrefix}${spec.serverRateLimitsOauthIntrospectWindow.env}`] as number,
					},
					register: {
						capacity: o[`${envPrefix}${spec.serverRateLimitsOauthRegisterCapacity.env}`] as number,
						window: o[`${envPrefix}${spec.serverRateLimitsOauthRegisterWindow.env}`] as number,
					},
					revoke: {
						capacity: o[`${envPrefix}${spec.serverRateLimitsOauthRevokeCapacity.env}`] as number,
						window: o[`${envPrefix}${spec.serverRateLimitsOauthRevokeWindow.env}`] as number,
					},
					token: {
						capacity: o[`${envPrefix}${spec.serverRateLimitsOauthTokenCapacity.env}`] as number,
						window: o[`${envPrefix}${spec.serverRateLimitsOauthTokenWindow.env}`] as number,
					},
				},
			},
		},
		request: {
			queryEnabled: o[`${envPrefix}${spec.requestQuery.env}`] as boolean,
			headerEnabled: o[`${envPrefix}${spec.requestAuthorizationHeader.env}`] as boolean,
			headerPrefix: o[`${envPrefix}${spec.requestHeaderPrefix.env}`] as string,
		},
	})).
	transform((o, c) => {
		if (o.internal) {
			o = {
				internal: o.internal,
				mcp: {
					transport: "streamable-http",
					dynamic: o.mcp.dynamic,
					toolsets: o.mcp.toolsets,
					tools: o.mcp.tools,
					enabledTools: o.mcp.enabledTools,
					disabledTools: o.mcp.disabledTools,
					session: o.mcp.session,
				},
				api: {
					userAgent: o.api.userAgent,
					shared: {
						baseUrl: "",
						authorization: "",
						apiKey: "",
						pat: "",
						username: "",
						password: "",
					},
					oauth: {
						baseUrl: "",
						clientId: "",
						clientSecret: "",
					},
				},
				oauth: {
					authToken: {
						algorithm: "",
						ttl: 0,
						secretKey: "",
					},
					stateToken: {
						algorithm: "",
						ttl: 0,
						secretKey: "",
					},
				},
				fileOperation: {
					interval: o.fileOperation.interval,
					timeout: o.fileOperation.timeout,
				},
				proxy: {
					hops: 0,
				},
				server: {
					baseUrl: "",
					host: o.server.host,
					port: o.server.port,
					allowedHostnames: [],
					cors: {
						mcp: {
							origin: [],
							maxAge: 0,
						},
						oauth: {
							origin: [],
							maxAge: 0,
						},
					},
					rateLimits: {
						mcp: {
							capacity: 0,
							window: 0,
						},
						oauth: {
							serverMetadata: {
								capacity: 0,
								window: 0,
							},
							resourceMetadata: {
								capacity: 0,
								window: 0,
							},
							authorize: {
								capacity: 0,
								window: 0,
							},
							callback: {
								capacity: 0,
								window: 0,
							},
							introspect: {
								capacity: 0,
								window: 0,
							},
							register: {
								capacity: 0,
								window: 0,
							},
							revoke: {
								capacity: 0,
								window: 0,
							},
							token: {
								capacity: 0,
								window: 0,
							},
						},
					},
				},
				request: {
					queryEnabled: false,
					headerEnabled: false,
					headerPrefix: "",
				},
			}
		}

		let to: ResolveToolsOptions = {
			toolsets: o.mcp.toolsets,
			enabledTools: o.mcp.enabledTools,
			disabledTools: o.mcp.disabledTools,
		}

		let t = resolveTools(to)

		o.mcp.toolsets = t.toolsets
		o.mcp.tools = t.tools

		if (o.mcp.tools.length === 0) {
			let i: z.core.$ZodSuperRefineIssue = {
				code: "custom",
				message: "No tools left",
			}
			c.addIssue(i)
		}

		if (
			o.api.shared.username &&
			!o.api.shared.password
		) {
			let i: z.core.$ZodSuperRefineIssue = {
				code: "custom",
				message: "No password",
			}
			c.addIssue(i)
		}

		if (
			!o.api.shared.username &&
			o.api.shared.password
		) {
			let i: z.core.$ZodSuperRefineIssue = {
				code: "custom",
				message: "No username",
			}
			c.addIssue(i)
		}

		if (
			(
				o.api.shared.authorization ||
				o.api.shared.apiKey ||
				o.api.shared.pat ||
				o.api.shared.username &&
				o.api.shared.password
			) &&
			!o.api.shared.baseUrl
		) {
			let i: z.core.$ZodSuperRefineIssue = {
				code: "custom",
				message: "No API base URL",
			}
			c.addIssue(i)
		}

		if (
			(
				o.mcp.transport === "sse" ||
				o.mcp.transport === "streamable-http" ||
				o.mcp.transport === "http"
			) &&
			o.api.oauth.baseUrl &&
			o.api.oauth.clientId &&
			!o.api.oauth.clientSecret
		) {
			let i: z.core.$ZodSuperRefineIssue = {
				code: "custom",
				message: "No OAuth client secret",
			}
			c.addIssue(i)
		}

		if (
			(
				o.mcp.transport === "sse" ||
				o.mcp.transport === "streamable-http" ||
				o.mcp.transport === "http"
			) &&
			o.api.oauth.baseUrl &&
			!o.api.oauth.clientId &&
			o.api.oauth.clientSecret
		) {
			let i: z.core.$ZodSuperRefineIssue = {
				code: "custom",
				message: "No OAuth client ID",
			}
			c.addIssue(i)
		}

		if (
			!o.internal &&
			(
				o.mcp.transport === "stdio" &&
				!o.api.shared.authorization &&
				!o.api.shared.apiKey &&
				!o.api.shared.pat &&
				!o.api.shared.username &&
				!o.api.shared.password ||
				(
					o.mcp.transport === "sse" ||
					o.mcp.transport === "streamable-http" ||
					o.mcp.transport === "http"
				) &&
				!o.api.shared.authorization &&
				!o.api.shared.apiKey &&
				!o.api.shared.pat &&
				!o.api.shared.username &&
				!o.api.shared.password &&
				!o.api.oauth.baseUrl &&
				!o.request.headerPrefix &&
				(
					!o.request.headerEnabled ||
					!o.request.queryEnabled
				)
			)
		) {
			let i: z.core.$ZodSuperRefineIssue = {
				code: "custom",
				message: "No authentication method",
			}
			c.addIssue(i)
		}

		if (
			o.mcp.transport === "stdio" &&
			(
				o.api.shared.authorization ||
				o.api.shared.apiKey ||
				o.api.shared.pat ||
				o.api.shared.username &&
				o.api.shared.password
			) &&
			Number(Boolean(o.api.shared.authorization)) +
			Number(Boolean(o.api.shared.apiKey)) +
			Number(Boolean(o.api.shared.pat)) +
			Number(
				Boolean(o.api.shared.username) &&
				Boolean(o.api.shared.password),
			) !== 1 ||
			(
				o.mcp.transport === "sse" ||
				o.mcp.transport === "streamable-http" ||
				o.mcp.transport === "http"
			) &&
			(
				o.api.shared.authorization ||
				o.api.shared.apiKey ||
				o.api.shared.pat ||
				o.api.shared.username &&
				o.api.shared.password ||
				o.api.oauth.baseUrl
			) &&
			Number(Boolean(o.api.shared.authorization)) +
			Number(Boolean(o.api.shared.apiKey)) +
			Number(Boolean(o.api.shared.pat)) +
			Number(
				Boolean(o.api.shared.username) &&
				Boolean(o.api.shared.password),
			) +
			Number(Boolean(o.api.oauth.baseUrl)) !== 1
		) {
			let i: z.core.$ZodSuperRefineIssue = {
				code: "custom",
				message: "Multiple authentication methods",
			}
			c.addIssue(i)
		}

		if (
			(
				o.mcp.transport === "sse" ||
				o.mcp.transport === "streamable-http" ||
				o.mcp.transport === "http"
			) &&
			o.api.oauth.baseUrl &&
			!o.server.baseUrl
		) {
			let i: z.core.$ZodSuperRefineIssue = {
				code: "custom",
				message: "No server base URL",
			}
			c.addIssue(i)
		}

		if (
			(
				o.mcp.transport === "sse" ||
				o.mcp.transport === "streamable-http" ||
				o.mcp.transport === "http"
			) &&
			!o.server.host
		) {
			let i: z.core.$ZodSuperRefineIssue = {
				code: "custom",
				message: "No server host",
			}
			c.addIssue(i)
		}

		return o
	})

export function redactEnv(c: Env): object {
	let m = "***"

	// todo: sensitivity must be determined by spec
	let s: string[] = [
		"root.api.shared.authorization",
		"root.api.shared.apiKey",
		"root.api.shared.pat",
		"root.api.shared.username",
		"root.api.shared.password",
		"root.api.oauth.clientSecret",
		"root.oauth.authToken.secretKey",
		"root.oauth.stateToken.secretKey",
	]

	let h = (v: unknown, p: string): unknown => {
		if (!v) {
			return
		}

		if (Array.isArray(v)) {
			if (v.length === 0) {
				return
			}

			return v
		}

		if (typeof v === "object") {
			if (Object.keys(v).length === 0) {
				return
			}

			let o: Record<string, unknown> = {}

			for (let [x, y] of Object.entries(v)) {
				let n = h(y, `${p}.${x}`)

				if (n) {
					o[x] = n
				}
			}

			if (Object.keys(o).length === 0) {
				return
			}

			return o
		}

		if (s.includes(p)) {
			return m
		}

		return v
	}

	let o = h(c, "root")

	return o as object
}

function prefault(v: spec.ItemDefault): string {
	switch (typeof v) {
	case "boolean":
		switch (v) {
		case true:
			return "1"
		case false:
			return "0"
		default:
			throw new Error("Unreachable")
		}
	case "number":
		return String(v)
	case "string":
		return v
	default:
		throw new Error("Unreachable")
	}
}
