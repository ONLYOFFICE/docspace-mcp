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

// todo: move this config description with config from app into own module

import * as mcp from "../lib/mcp.ts"
import * as meta from "../lib/meta.ts"

const availableTransports: string[] = [
	"stdio",
	"sse",
	"streamable-http",
	"http",
]

const availableToolsets = (() => {
	let a: string[] = []
	for (let s of mcp.toolsetInfos) {
		a.push(s.name)
	}
	return a
})()

const availableTools = (() => {
	let a: string[] = []
	for (let s of mcp.toolsetInfos) {
		for (let t of s.tools) {
			a.push(t.name)
		}
	}
	return a
})()

export interface Option {
	env: string
	header: string
	title: string
	description: string
	transports: Transport[]
	distribution: Distribution[]
	type: "boolean" | "number" | "string"
	choices: string[]
	default: boolean | number | string
	sensitive: boolean
}

export type Transport = "stdio" | "sse" | "streamable-http"

export type Distribution = "js" | "mcpb" | "oci"

export const options: Option[] = [
	{
		env: "DOCSPACE_TRANSPORT",
		header: "",
		title: "Transport",
		description: "The transport protocol to use for communication with the DocSpace MCP server.",
		transports: ["stdio", "sse", "streamable-http"],
		distribution: ["js", "oci"],
		type: "string",
		choices: availableTransports,
		default: "stdio",
		sensitive: false,
	},
	{
		env: "DOCSPACE_DYNAMIC",
		header: "X-Mcp-Dynamic",
		title: "Meta Tools",
		description: "The flag that indicates whether the DocSpace MCP server should use meta tools.",
		transports: ["stdio", "sse", "streamable-http"],
		distribution: ["js", "oci"],
		type: "boolean",
		choices: [],
		default: false,
		sensitive: false,
	},
	{
		env: "DOCSPACE_TOOLSETS",
		header: "X-Mcp-Toolsets",
		title: "Toolsets",
		description: "The list of toolsets to enable for the DocSpace MCP server.",
		transports: ["stdio", "sse", "streamable-http"],
		distribution: ["js", "oci"],
		type: "string",
		choices: availableToolsets,
		default: "all",
		sensitive: false,
	},
	{
		env: "DOCSPACE_ENABLED_TOOLS",
		header: "X-Mcp-Enabled-Tools",
		title: "Enabled Tools",
		description: "The list of tools to enable for the DocSpace MCP server.",
		transports: ["stdio", "sse", "streamable-http"],
		distribution: ["js", "oci"],
		type: "string",
		choices: availableTools,
		default: "",
		sensitive: false,
	},
	{
		env: "DOCSPACE_DISABLED_TOOLS",
		header: "X-Mcp-Disabled-Tools",
		title: "Disabled Tools",
		description: "The list of tools to disable for the DocSpace MCP server.",
		transports: ["stdio", "sse", "streamable-http"],
		distribution: ["js", "oci"],
		type: "string",
		choices: availableTools,
		default: "",
		sensitive: false,
	},
	{
		env: "DOCSPACE_SESSION_TTL",
		header: "",
		title: "Session TTL",
		description: "The time-to-live (TTL) for HTTP sessions in milliseconds.",
		transports: ["sse", "streamable-http"],
		distribution: ["js", "oci"],
		type: "number",
		choices: [],
		default: 28800000, // 8 hours
		sensitive: false,
	},
	{
		env: "DOCSPACE_SESSION_INTERVAL",
		header: "",
		title: "Session Interval",
		description: "The interval for checking HTTP sessions for expiration in milliseconds.",
		transports: ["sse", "streamable-http"],
		distribution: ["js", "oci"],
		type: "number",
		choices: [],
		default: 240000, // 4 minutes
		sensitive: false,
	},
	{
		env: "DOCSPACE_USER_AGENT",
		header: "",
		title: "User Agent",
		description: "The user agent to include in the `User-Agent` header for DocSpace API requests.",
		transports: ["stdio", "sse", "streamable-http"],
		distribution: ["js", "oci"],
		type: "string",
		choices: [],
		default: `${meta.name} v${meta.version}`,
		sensitive: false,
	},
	{
		env: "DOCSPACE_BASE_URL",
		header: "X-Mcp-Base-Url",
		title: "Base URL",
		description: "The base URL of the DocSpace instance for API requests.",
		transports: ["stdio", "sse", "streamable-http"],
		distribution: ["js", "mcpb", "oci"],
		type: "string",
		choices: [],
		default: "",
		sensitive: false,
	},
	{
		env: "DOCSPACE_AUTHORIZATION",
		header: "",
		title: "Authorization",
		description: "The raw value to include in the Authorization header for DocSpace API requests.",
		transports: ["stdio", "sse", "streamable-http"],
		distribution: ["js", "oci"],
		type: "string",
		choices: [],
		default: "",
		sensitive: true,
	},
	{
		env: "DOCSPACE_API_KEY",
		header: "X-Mcp-Api-Key",
		title: "API Key",
		description: "The API key for accessing the DocSpace API.",
		transports: ["stdio", "sse", "streamable-http"],
		distribution: ["js", "mcpb", "oci"],
		type: "string",
		choices: [],
		default: "",
		sensitive: true,
	},
	{
		env: "DOCSPACE_AUTH_TOKEN",
		header: "X-Mcp-Auth-Token",
		title: "Personal Access Token",
		description: "The Personal Access Token (PAT) for accessing the DocSpace API.",
		transports: ["stdio", "sse", "streamable-http"],
		distribution: ["js", "oci"],
		type: "string",
		choices: [],
		default: "",
		sensitive: true,
	},
	{
		env: "DOCSPACE_USERNAME",
		header: "X-Mcp-Username",
		title: "Username",
		description: "The username for accessing the DocSpace API using basic authentication.",
		transports: ["stdio", "sse", "streamable-http"],
		distribution: ["js", "oci"],
		type: "string",
		choices: [],
		default: "",
		sensitive: false,
	},
	{
		env: "DOCSPACE_PASSWORD",
		header: "X-Mcp-Password",
		title: "Password",
		description: "The password for accessing the DocSpace API using basic authentication.",
		transports: ["stdio", "sse", "streamable-http"],
		distribution: ["js", "oci"],
		type: "string",
		choices: [],
		default: "",
		sensitive: true,
	},
	{
		env: "DOCSPACE_HOST",
		header: "",
		title: "Server Host",
		description: "The host to bind the DocSpace MCP server to.",
		transports: ["sse", "streamable-http"],
		distribution: ["js", "oci"],
		type: "string",
		choices: [],
		default: "127.0.0.1",
		sensitive: false,
	},
	{
		env: "DOCSPACE_PORT",
		header: "",
		title: "Server Port",
		description: "The port to bind the DocSpace MCP server to.",
		transports: ["sse", "streamable-http"],
		distribution: ["js", "oci"],
		type: "number",
		choices: [],
		default: 8080,
		sensitive: false,
	},
	{
		env: "DOCSPACE_SERVER_PROXY_HOPS",
		header: "",
		title: "Server Proxy Hops",
		description: "The number of proxy servers between the DocSpace MCP server and the client.",
		transports: ["sse", "streamable-http"],
		distribution: ["js", "oci"],
		type: "number",
		choices: [],
		default: 0,
		sensitive: false,
	},
	{
		env: "DOCSPACE_SERVER_CORS_MCP_ORIGIN",
		header: "",
		title: "Server CORS MCP Origin",
		description: "The list of allowed origins to include in the Access-Control-Allow-Origin header for CORS requests to MCP endpoints.",
		transports: ["sse", "streamable-http"],
		distribution: ["js", "oci"],
		type: "string",
		choices: [],
		default: "*",
		sensitive: false,
	},
	{
		env: "DOCSPACE_SERVER_CORS_MCP_MAX_AGE",
		header: "",
		title: "Server CORS MCP Maximum Age",
		description: "The maximum age in milliseconds to include in the Access-Control-Max-Age header for CORS requests to MCP endpoints.",
		transports: ["sse", "streamable-http"],
		distribution: ["js", "oci"],
		type: "number",
		choices: [],
		default: 86400000, // 1 day
		sensitive: false,
	},
	{
		env: "DOCSPACE_SERVER_RATE_LIMITS_MCP_CAPACITY",
		header: "",
		title: "Server Rate Limits MCP Capacity",
		description: "The maximum number of requests allowed per window for the MCP endpoints.",
		transports: ["sse", "streamable-http"],
		distribution: ["js", "oci"],
		type: "number",
		choices: [],
		default: 1000,
		sensitive: false,
	},
	{
		env: "DOCSPACE_SERVER_RATE_LIMITS_MCP_WINDOW",
		header: "",
		title: "Server Rate Limits MCP Window",
		description: "The time window in milliseconds for the rate limit for the MCP endpoints.",
		transports: ["sse", "streamable-http"],
		distribution: ["js", "oci"],
		type: "number",
		choices: [],
		default: 1000, // 1 second
		sensitive: false,
	},
	{
		env: "DOCSPACE_REQUEST_QUERY",
		header: "",
		title: "Request Query",
		description: "The flag that indicates whether the DocSpace MCP server should accept configuration via query parameters in incoming requests.",
		transports: ["sse", "streamable-http"],
		distribution: ["js", "oci"],
		type: "boolean",
		choices: [],
		default: true,
		sensitive: false,
	},
	{
		env: "DOCSPACE_REQUEST_AUTHORIZATION_HEADER",
		header: "",
		title: "Request Authorization Header",
		description: "The flag that indicates whether the DocSpace MCP server should check for the Authorization header in incoming requests.",
		transports: ["sse", "streamable-http"],
		distribution: ["js", "oci"],
		type: "boolean",
		choices: [],
		default: true,
		sensitive: false,
	},
	{
		env: "DOCSPACE_REQUEST_HEADER_PREFIX",
		header: "",
		title: "Request Header Prefix",
		description: "The prefix to use with custom configuration headers for the DocSpace MCP server.",
		transports: ["sse", "streamable-http"],
		distribution: ["js", "oci"],
		type: "string",
		choices: [],
		default: "x-mcp-",
		sensitive: false,
	},
]
