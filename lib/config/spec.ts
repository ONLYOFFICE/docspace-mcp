/**
 * @module
 * @mergeModuleWith config/spec
 */

import * as meta from "../meta.ts"

export type Item = {
	title: string
	description: string
	distributions: ItemDistribution[]
	transports: ItemTransport[]
	type: ItemType
	choices: string[]
	default: ItemDefault
	sensitive: boolean
	env: string
	query: string
	header: string
}

export type ItemDistribution = "js" | "mcpb" | "oci"

export type ItemTransport = "stdio" | "sse" | "streamable-http"

export type ItemType = "boolean" | "number" | "string"

export type ItemAlgorithmChoice = "HS256" | "HS384" | "HS512"

export type ItemTransportChoice = "stdio" | "sse" | "streamable-http" | "http"

export type ItemDefault = boolean | number | string

export const transport: Item = {
	title: "Transport",
	description: "The transport protocol to use for communication with the MCP server.",
	distributions: ["js", "oci"],
	transports: ["stdio", "sse", "streamable-http"],
	type: "string",
	choices: ["stdio", "sse", "streamable-http", "http"],
	default: "stdio",
	sensitive: false,
	env: "TRANSPORT",
	query: "",
	header: "",
}

export const dynamic: Item = {
	title: "Meta Tools",
	description: "The flag that indicates whether the MCP server should use meta tools.",
	distributions: ["js", "oci"],
	transports: ["stdio", "sse", "streamable-http"],
	type: "boolean",
	choices: [],
	default: false,
	sensitive: false,
	env: "DYNAMIC",
	query: "dynamic",
	header: "Dynamic",
}

export const toolsets: Item = {
	title: "Toolsets",
	description: "The list of toolsets to enable for the MCP server.",
	distributions: ["js", "oci"],
	transports: ["stdio", "sse", "streamable-http"],
	type: "string",
	choices: [],
	default: "all",
	sensitive: false,
	env: "TOOLSETS",
	query: "toolsets",
	header: "Toolsets",
}

export const enabledTools: Item = {
	title: "Enabled Tools",
	description: "The list of tools to enable for the MCP server.",
	distributions: ["js", "oci"],
	transports: ["stdio", "sse", "streamable-http"],
	type: "string",
	choices: [],
	default: "",
	sensitive: false,
	env: "ENABLED_TOOLS",
	query: "enabled_tools",
	header: "Enabled-Tools",
}

export const disabledTools: Item = {
	title: "Disabled Tools",
	description: "The list of tools to disable for the MCP server.",
	distributions: ["js", "oci"],
	transports: ["stdio", "sse", "streamable-http"],
	type: "string",
	choices: [],
	default: "",
	sensitive: false,
	env: "DISABLED_TOOLS",
	query: "disabled_tools",
	header: "Disabled-Tools",
}

export const sessionTtl: Item = {
	title: "Session TTL",
	description: "The time-to-live (TTL) for HTTP sessions in milliseconds.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 28800000, // 8 hours
	sensitive: false,
	env: "SESSION_TTL",
	query: "",
	header: "",
}

export const sessionInterval: Item = {
	title: "Session Interval",
	description: "The interval for checking HTTP sessions for expiration in milliseconds.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 240000, // 4 minutes
	sensitive: false,
	env: "SESSION_INTERVAL",
	query: "",
	header: "",
}

export const userAgent: Item = {
	title: "User Agent",
	description: "The user agent to include in the User-Agent header for API requests.",
	distributions: ["js", "oci"],
	transports: ["stdio", "sse", "streamable-http"],
	type: "string",
	choices: [],
	default: `${meta.name} v${meta.version}`,
	sensitive: false,
	env: "USER_AGENT",
	query: "",
	header: "",
}

export const baseUrl: Item = {
	title: "Base URL",
	description: "The base URL of the DocSpace instance for API requests.",
	distributions: ["js", "mcpb", "oci"],
	transports: ["stdio", "sse", "streamable-http"],
	type: "string",
	choices: [],
	default: "",
	sensitive: false,
	env: "BASE_URL",
	query: "",
	header: "Base-Url",
}

export const authorization: Item = {
	title: "Authorization",
	description: "The raw value to include in the Authorization header for API requests.",
	distributions: ["js", "oci"],
	transports: ["stdio", "sse", "streamable-http"],
	type: "string",
	choices: [],
	default: "",
	sensitive: true,
	env: "AUTHORIZATION",
	query: "",
	header: "",
}

export const apiKey: Item = {
	title: "API Key",
	description: "The API key for accessing the API.",
	distributions: ["js", "mcpb", "oci"],
	transports: ["stdio", "sse", "streamable-http"],
	type: "string",
	choices: [],
	default: "",
	sensitive: true,
	env: "API_KEY",
	query: "",
	header: "Api-Key",
}

export const authToken: Item = {
	title: "Personal Access Token",
	description: "The Personal Access Token (PAT) for accessing the API.",
	distributions: ["js", "oci"],
	transports: ["stdio", "sse", "streamable-http"],
	type: "string",
	choices: [],
	default: "",
	sensitive: true,
	env: "AUTH_TOKEN",
	query: "",
	header: "Auth-Token",
}

export const username: Item = {
	title: "Username",
	description: "The username for accessing the API using basic authentication.",
	distributions: ["js", "oci"],
	transports: ["stdio", "sse", "streamable-http"],
	type: "string",
	choices: [],
	default: "",
	sensitive: false,
	env: "USERNAME",
	query: "",
	header: "Username",
}

export const password: Item = {
	title: "Password",
	description: "The password for accessing the API using basic authentication.",
	distributions: ["js", "oci"],
	transports: ["stdio", "sse", "streamable-http"],
	type: "string",
	choices: [],
	default: "",
	sensitive: true,
	env: "PASSWORD",
	query: "",
	header: "Password",
}

export const oauthBaseUrl: Item = {
	title: "OAuth Base URL",
	description: "The base URL of the DocSpace OAuth service for OAuth requests.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "string",
	choices: [],
	default: "",
	sensitive: false,
	env: "OAUTH_BASE_URL",
	query: "",
	header: "",
}

export const oauthClientId: Item = {
	title: "OAuth Client ID",
	description: "The client ID of the OAuth application.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "string",
	choices: [],
	default: "",
	sensitive: false,
	env: "OAUTH_CLIENT_ID",
	query: "",
	header: "",
}

export const oauthClientSecret: Item = {
	title: "OAuth Client Secret",
	description: "The client secret of the OAuth application.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "string",
	choices: [],
	default: "",
	sensitive: true,
	env: "OAUTH_CLIENT_SECRET",
	query: "",
	header: "",
}

export const oauthAuthTokenAlgorithm: Item = {
	title: "OAuth Auth Token Algorithm",
	description: "The algorithm to use for signing OAuth access tokens.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "string",
	choices: ["HS256", "HS384", "HS512"],
	default: "HS256",
	sensitive: false,
	env: "OAUTH_AUTH_TOKEN_ALGORITHM",
	query: "",
	header: "",
}

export const oauthAuthTokenTtl: Item = {
	title: "OAuth Auth Token TTL",
	description: "The time-to-live (TTL) for OAuth access tokens in milliseconds.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 3600000, // 1 hour
	sensitive: false,
	env: "OAUTH_AUTH_TOKEN_TTL",
	query: "",
	header: "",
}

export const oauthAuthTokenSecretKey: Item = {
	title: "OAuth Auth Token Secret Key",
	description: "The secret key to use for signing OAuth access tokens.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "string",
	choices: [],
	default: "",
	sensitive: true,
	env: "OAUTH_AUTH_TOKEN_SECRET_KEY",
	query: "",
	header: "",
}

export const oauthStateTokenAlgorithm: Item = {
	title: "OAuth State Token Algorithm",
	description: "The algorithm to use for signing OAuth state tokens.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "string",
	choices: ["HS256", "HS384", "HS512"],
	default: "HS256",
	sensitive: false,
	env: "OAUTH_STATE_TOKEN_ALGORITHM",
	query: "",
	header: "",
}

export const oauthStateTokenTtl: Item = {
	title: "OAuth State Token TTL",
	description: "The time-to-live (TTL) for OAuth state tokens in milliseconds.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 3600000, // 1 hour
	sensitive: false,
	env: "OAUTH_STATE_TOKEN_TTL",
	query: "",
	header: "",
}

export const oauthStateTokenSecretKey: Item = {
	title: "OAuth State Token Secret Key",
	description: "The secret key to use for signing OAuth state tokens.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "string",
	choices: [],
	default: "",
	sensitive: true,
	env: "OAUTH_STATE_TOKEN_SECRET_KEY",
	query: "",
	header: "",
}

export const fileOperationInterval: Item = {
	title: "File Operation Interval",
	description: "The interval for polling the status of in-progress file operations in milliseconds.",
	distributions: ["js", "mcpb", "oci"],
	transports: ["stdio", "sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 300, // 300 milliseconds
	sensitive: false,
	env: "FILE_OPERATION_INTERVAL",
	query: "",
	header: "",
}

export const fileOperationTimeout: Item = {
	title: "File Operation Timeout",
	description: "The maximum time to wait for a file operation to complete in milliseconds.",
	distributions: ["js", "mcpb", "oci"],
	transports: ["stdio", "sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 3600000, // 1 hour
	sensitive: false,
	env: "FILE_OPERATION_TIMEOUT",
	query: "",
	header: "",
}

export const serverBaseUrl: Item = {
	title: "Server Base URL",
	description: "The base URL of the server.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "string",
	choices: [],
	default: "",
	sensitive: false,
	env: "SERVER_BASE_URL",
	query: "",
	header: "",
}

export const host: Item = {
	title: "Server Host",
	description: "The host to bind the server to.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "string",
	choices: [],
	default: "127.0.0.1",
	sensitive: false,
	env: "HOST",
	query: "",
	header: "",
}

export const port: Item = {
	title: "Server Port",
	description: "The port to bind the server to.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 8080,
	sensitive: false,
	env: "PORT",
	query: "",
	header: "",
}

export const proxyHops: Item = {
	title: "Server Proxy Hops",
	description: "The number of proxy servers between the server and the client.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 0,
	sensitive: false,
	env: "PROXY_HOPS",
	query: "",
	header: "",
}

export const serverAllowedHostnames: Item = {
	title: "Server Allowed Hostnames",
	description: "The list of allowed hostnames.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "string",
	choices: [],
	default: "localhost,127.0.0.1,[::1]",
	sensitive: false,
	env: "SERVER_ALLOWED_HOSTNAMES",
	query: "",
	header: "",
}

export const serverCorsMcpOrigin: Item = {
	title: "Server CORS MCP Origin",
	description: "The list of allowed origins to include in the Access-Control-Allow-Origin header for CORS requests to MCP endpoints.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "string",
	choices: [],
	default: "*",
	sensitive: false,
	env: "SERVER_CORS_MCP_ORIGIN",
	query: "",
	header: "",
}

export const serverCorsMcpMaxAge: Item = {
	title: "Server CORS MCP Maximum Age",
	description: "The maximum age in milliseconds to include in the Access-Control-Max-Age header for CORS requests to MCP endpoints.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 86400000, // 1 day
	sensitive: false,
	env: "SERVER_CORS_MCP_MAX_AGE",
	query: "",
	header: "",
}

export const serverCorsOauthOrigin: Item = {
	title: "Server CORS OAuth Origin",
	description: "The list of allowed origins to include in the Access-Control-Allow-Origin header for CORS requests to OAuth endpoints.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "string",
	choices: [],
	default: "*",
	sensitive: false,
	env: "SERVER_CORS_OAUTH_ORIGIN",
	query: "",
	header: "",
}

export const serverCorsOauthMaxAge: Item = {
	title: "Server CORS OAuth Maximum Age",
	description: "The maximum age in milliseconds to include in the Access-Control-Max-Age header for CORS requests to OAuth endpoints.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 86400000, // 1 day
	sensitive: false,
	env: "SERVER_CORS_OAUTH_MAX_AGE",
	query: "",
	header: "",
}

export const serverRateLimitsMcpCapacity: Item = {
	title: "Server Rate Limits MCP Capacity",
	description: "The maximum number of requests allowed per window for the MCP endpoints.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 1000,
	sensitive: false,
	env: "SERVER_RATE_LIMITS_MCP_CAPACITY",
	query: "",
	header: "",
}

export const serverRateLimitsMcpWindow: Item = {
	title: "Server Rate Limits MCP Window",
	description: "The time window in milliseconds for the rate limit for the MCP endpoints.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 1000, // 1 second
	sensitive: false,
	env: "SERVER_RATE_LIMITS_MCP_WINDOW",
	query: "",
	header: "",
}

export const serverRateLimitsOauthServerMetadataCapacity: Item = {
	title: "Server Rate Limits OAuth Server Metadata Capacity",
	description: "The maximum number of requests allowed per window for the OAuth server metadata endpoint.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 200,
	sensitive: false,
	env: "SERVER_RATE_LIMITS_OAUTH_SERVER_METADATA_CAPACITY",
	query: "",
	header: "",
}

export const serverRateLimitsOauthServerMetadataWindow: Item = {
	title: "Server Rate Limits OAuth Server Metadata Window",
	description: "The time window in milliseconds for the rate limit for the OAuth server metadata endpoint.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 60000, // 1 minute
	sensitive: false,
	env: "SERVER_RATE_LIMITS_OAUTH_SERVER_METADATA_WINDOW",
	query: "",
	header: "",
}

export const serverRateLimitsOauthResourceMetadataCapacity: Item = {
	title: "Server Rate Limits OAuth Resource Metadata Capacity",
	description: "The maximum number of requests allowed per window for the OAuth resource metadata endpoint.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 200,
	sensitive: false,
	env: "SERVER_RATE_LIMITS_OAUTH_RESOURCE_METADATA_CAPACITY",
	query: "",
	header: "",
}

export const serverRateLimitsOauthResourceMetadataWindow: Item = {
	title: "Server Rate Limits OAuth Resource Metadata Window",
	description: "The time window in milliseconds for the rate limit for the OAuth resource metadata endpoint.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 60000, // 1 minute
	sensitive: false,
	env: "SERVER_RATE_LIMITS_OAUTH_RESOURCE_METADATA_WINDOW",
	query: "",
	header: "",
}

export const serverRateLimitsOauthAuthorizeCapacity: Item = {
	title: "Server Rate Limits OAuth Authorize Capacity",
	description: "The maximum number of requests allowed per window for the OAuth authorization endpoint.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 200,
	sensitive: false,
	env: "SERVER_RATE_LIMITS_OAUTH_AUTHORIZE_CAPACITY",
	query: "",
	header: "",
}

export const serverRateLimitsOauthAuthorizeWindow: Item = {
	title: "Server Rate Limits OAuth Authorize Window",
	description: "The time window in milliseconds for the rate limit for the OAuth authorization endpoint.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 60000, // 1 minute
	sensitive: false,
	env: "SERVER_RATE_LIMITS_OAUTH_AUTHORIZE_WINDOW",
	query: "",
	header: "",
}

export const serverRateLimitsOauthCallbackCapacity: Item = {
	title: "Server Rate Limits OAuth Callback Capacity",
	description: "The maximum number of requests allowed per window for the OAuth callback endpoint.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 200,
	sensitive: false,
	env: "SERVER_RATE_LIMITS_OAUTH_CALLBACK_CAPACITY",
	query: "",
	header: "",
}

export const serverRateLimitsOauthCallbackWindow: Item = {
	title: "Server Rate Limits OAuth Callback Window",
	description: "The time window in milliseconds for the rate limit for the OAuth callback endpoint.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 60000, // 1 minute
	sensitive: false,
	env: "SERVER_RATE_LIMITS_OAUTH_CALLBACK_WINDOW",
	query: "",
	header: "",
}

export const serverRateLimitsOauthIntrospectCapacity: Item = {
	title: "Server Rate Limits OAuth Introspect Capacity",
	description: "The maximum number of requests allowed per window for the OAuth introspection endpoint.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 10,
	sensitive: false,
	env: "SERVER_RATE_LIMITS_OAUTH_INTROSPECT_CAPACITY",
	query: "",
	header: "",
}

export const serverRateLimitsOauthIntrospectWindow: Item = {
	title: "Server Rate Limits OAuth Introspect Window",
	description: "The time window in milliseconds for the rate limit for the OAuth introspection endpoint.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 60000, // 1 minute
	sensitive: false,
	env: "SERVER_RATE_LIMITS_OAUTH_INTROSPECT_WINDOW",
	query: "",
	header: "",
}

export const serverRateLimitsOauthRegisterCapacity: Item = {
	title: "Server Rate Limits OAuth Register Capacity",
	description: "The maximum number of requests allowed per window for the OAuth client registration endpoint.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 10,
	sensitive: false,
	env: "SERVER_RATE_LIMITS_OAUTH_REGISTER_CAPACITY",
	query: "",
	header: "",
}

export const serverRateLimitsOauthRegisterWindow: Item = {
	title: "Server Rate Limits OAuth Register Window",
	description: "The time window in milliseconds for the rate limit for the OAuth client registration endpoint.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 60000, // 1 minute
	sensitive: false,
	env: "SERVER_RATE_LIMITS_OAUTH_REGISTER_WINDOW",
	query: "",
	header: "",
}

export const serverRateLimitsOauthRevokeCapacity: Item = {
	title: "Server Rate Limits OAuth Revoke Capacity",
	description: "The maximum number of requests allowed per window for the OAuth token revocation endpoint.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 10,
	sensitive: false,
	env: "SERVER_RATE_LIMITS_OAUTH_REVOKE_CAPACITY",
	query: "",
	header: "",
}

export const serverRateLimitsOauthRevokeWindow: Item = {
	title: "Server Rate Limits OAuth Revoke Window",
	description: "The time window in milliseconds for the rate limit for the OAuth token revocation endpoint.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 60000, // 1 minute
	sensitive: false,
	env: "SERVER_RATE_LIMITS_OAUTH_REVOKE_WINDOW",
	query: "",
	header: "",
}

export const serverRateLimitsOauthTokenCapacity: Item = {
	title: "Server Rate Limits OAuth Token Capacity",
	description: "The maximum number of requests allowed per window for the OAuth token endpoint.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 10,
	sensitive: false,
	env: "SERVER_RATE_LIMITS_OAUTH_TOKEN_CAPACITY",
	query: "",
	header: "",
}

export const serverRateLimitsOauthTokenWindow: Item = {
	title: "Server Rate Limits OAuth Token Window",
	description: "The time window in milliseconds for the rate limit for the OAuth token endpoint.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "number",
	choices: [],
	default: 60000, // 1 minute
	sensitive: false,
	env: "SERVER_RATE_LIMITS_OAUTH_TOKEN_WINDOW",
	query: "",
	header: "",
}

export const requestQuery: Item = {
	title: "Request Query",
	description: "The flag that indicates whether the server should accept configuration via query parameters in incoming requests.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "boolean",
	choices: [],
	default: true,
	sensitive: false,
	env: "REQUEST_QUERY",
	query: "",
	header: "",
}

export const requestAuthorizationHeader: Item = {
	title: "Request Authorization Header",
	description: "The flag that indicates whether the server should check for the Authorization header in incoming requests.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "boolean",
	choices: [],
	default: true,
	sensitive: false,
	env: "REQUEST_AUTHORIZATION_HEADER",
	query: "",
	header: "",
}

export const requestHeaderPrefix: Item = {
	title: "Request Header Prefix",
	description: "The prefix to use with custom configuration headers.",
	distributions: ["js", "oci"],
	transports: ["sse", "streamable-http"],
	type: "string",
	choices: [],
	default: "X-Mcp-",
	sensitive: false,
	env: "REQUEST_HEADER_PREFIX",
	query: "",
	header: "",
}
