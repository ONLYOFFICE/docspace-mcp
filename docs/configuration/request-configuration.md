# Request Configuration

This document describes how to configure the DocSpace MCP server behavior on the
request level using custom HTTP headers. Request configuration is only available
for HTTP-like transports.

## Contents

- [Options](#options)
	- [MCP General Options](#mcp-general-options)
		- [X-Mcp-Dynamic](#x-mcp-dynamic)
		- [X-Mcp-Toolsets](#x-mcp-toolsets)
		- [X-Mcp-Enabled-Tools](#x-mcp-enabled-tools)
		- [X-Mcp-Disabled-Tools](#x-mcp-disabled-tools)
	- [API Shared Options](#api-shared-options)
		- [X-Mcp-Base-Url](#x-mcp-base-url)
		- [Authorization](#authorization)
		- [X-Mcp-Api-Key](#x-mcp-api-key)
		- [X-Mcp-Auth-Token](#x-mcp-auth-token)
		- [X-Mcp-Username](#x-mcp-username)
		- [X-Mcp-Password](#x-mcp-password)
- [Examples](#examples)
	- [Authentication with API Key](#authentication-with-api-key)
	- [Custom Tool Selection](#custom-tool-selection)

## Options

Configuration options are grouped into categories based on their purpose.

### MCP General Options

The following options are used to configure the general behavior of the DocSpace
MCP server at the MCP server level.

#### X-Mcp-Dynamic

The flag that indicates whether the DocSpace MCP server should use meta tools.

This option is complementary to [`X-Mcp-Toolsets`], [`X-Mcp-Enabled-Tools`], and
[`X-Mcp-Disabled-Tools`].

##### Signature

- Type: boolean
- Variants (true): `yes`, `y`, `true`, `1`
- Variants (false): `no`, `n`, `false`, `0`
- Attributes: trimmable, case-insensitive

##### References

- [DocSpace MCP: Meta Tools]

#### X-Mcp-Toolsets

The list of toolsets to enable for the DocSpace MCP server.

The available list of toolsets for this options depends on the DocSpace MCP
server global configuration.

##### Signature

- Type: comma-separated list of toolset names
- Attributes: trimmable, case-insensitive
- Example: `files,people`

##### References

- [DocSpace MCP: Toolsets]
- [DocSpace MCP: Tools Resolution]

#### X-Mcp-Enabled-Tools

The list of tools to enable for the DocSpace MCP server.

The available list of tools for this options depends on the DocSpace MCP server
global configuration.

##### Signature

- Type: comma-separated list of tool names
- Attributes: trimmable, case-insensitive
- Example: `get_file,get_all_people`

##### References

- [DocSpace MCP: Tools]
- [DocSpace MCP: Tools Resolution]

#### X-Mcp-Disabled-Tools

The list of tools to disable for the DocSpace MCP server.

The available list of tools for this options depends on the DocSpace MCP server
global configuration.

##### Signature

- Type: comma-separated list of tool names
- Attributes: trimmable, case-insensitive
- Example: `get_file,get_all_people`

##### References

- [DocSpace MCP: Tools]
- [DocSpace MCP: Tools Resolution]

### API Shared Options

The following options are used to configure the behavior for DocSpace API
requests to common DocSpace services (e.g., files, people, etc.).

#### X-Mcp-Base-Url

The base URL of the DocSpace instance for API requests.

The base URL must use HTTP or HTTPS scheme without search parameters or hash
fragments.

This option is not available if the DocSpace MCP server is configured to use
OAuth authentication.

This option is required if either [`Authorization`], [`X-Mcp-Api-Key`],
[`X-Mcp-Auth-Token`], or the [`X-Mcp-Username`]/[`X-Mcp-Password`] pair is set.

##### Signature

- Type: url
- Attributes: trimmable
- Example: `https://your-instance.onlyoffice.com/`

#### Authorization

The raw value to include in the `Authorization` header for DocSpace API
requests.

This option is not available if the DocSpace MCP server is configured to ignore
the `Authorization` header in incoming requests.

This option is not available if the DocSpace MCP server is configured to use
OAuth authentication.

This option is required if the DocSpace MCP server is configured without
authentication, and neither [`X-Mcp-Api-Key`], [`X-Mcp-Auth-Token`], nor the
[`X-Mcp-Username`]/[`X-Mcp-Password`] pair is set.

This option is mutually exclusive with [`X-Mcp-Api-Key`], [`X-Mcp-Auth-Token`],
and the [`X-Mcp-Username`]/[`X-Mcp-Password`] pair if the DocSpace MCP server is
configured to use non-OAuth authentication.

##### Signature

- Type: string
- Attributes: sensitive, trimmable
- Example: `Bearer sk-a499e...`

##### References

- [DocSpace API: API Keys]
- [DocSpace API: Personal Access Tokens]
- [DocSpace API: Basic Authentication]
- [DocSpace MCP: Authentication Resolution]

#### X-Mcp-Api-Key

The API key for accessing the DocSpace API.

This option is not available if the DocSpace MCP server is configured to use
OAuth authentication.

This option is required if the DocSpace MCP server is configured without
authentication, and neither [`Authorization`], [`X-Mcp-Auth-Token`], nor the
[`X-Mcp-Username`]/[`X-Mcp-Password`] pair is set.

This option is mutually exclusive with [`Authorization`], [`X-Mcp-Auth-Token`],
and the [`X-Mcp-Username`]/[`X-Mcp-Password`] pair if the DocSpace MCP server is
configured to use non-OAuth authentication.

##### Signature

- Type: string
- Attributes: sensitive, trimmable
- Example: `sk-a499e...`

##### References

- [DocSpace API: API Keys]
- [DocSpace MCP: Authentication Resolution]

#### X-Mcp-Auth-Token

The Personal Access Token (PAT) for accessing the DocSpace API.

This option is not available if the DocSpace MCP server is configured to use
OAuth authentication.

This option is required if the DocSpace MCP server is configured without
authentication, and neither [`Authorization`], [`X-Mcp-Api-Key`], nor the
[`X-Mcp-Username`]/[`X-Mcp-Password`] pair is set.

This option is mutually exclusive with [`Authorization`], [`X-Mcp-Api-Key`],
and the [`X-Mcp-Username`]/[`X-Mcp-Password`] pair if the DocSpace MCP server is
configured to use non-OAuth authentication.

##### Signature

- Type: string
- Attributes: sensitive, trimmable
- Example: `Fe4Hrgl6...`

##### References

- [DocSpace API: Personal Access Tokens]
- [DocSpace MCP: Authentication Resolution]

#### X-Mcp-Username

The username for accessing the DocSpace API using basic authentication.

This option is used in conjunction with [`X-Mcp-Password`].

This option is not available if the DocSpace MCP server is configured to use
OAuth authentication.

This option is required if the DocSpace MCP server is configured without
authentication, and neither [`Authorization`], [`X-Mcp-Api-Key`], nor
[`X-Mcp-Auth-Token`] is set.

This option is mutually exclusive with [`Authorization`], [`X-Mcp-Api-Key`],
and [`X-Mcp-Auth-Token`] if the DocSpace MCP server is configured to use
non-OAuth authentication.

##### Signature

- Type: string
- Attributes: sensitive, trimmable
- Example: `henry.milton@onlyoffice.com`

##### References

- [DocSpace API: Basic Authentication]
- [DocSpace MCP: Authentication Resolution]

#### X-Mcp-Password

The password for accessing the DocSpace API using basic authentication.

This option is used in conjunction with [`X-Mcp-Username`].

This option is not available if the DocSpace MCP server is configured to use
OAuth authentication.

This option is required if the DocSpace MCP server is configured without
authentication, and neither [`Authorization`], [`X-Mcp-Api-Key`], nor
[`X-Mcp-Auth-Token`] is set.

This option is mutually exclusive with [`Authorization`], [`X-Mcp-Api-Key`],
and [`X-Mcp-Auth-Token`] if the DocSpace MCP server is configured to use
non-OAuth authentication.

##### Signature

- Type: string
- Attributes: sensitive, trimmable
- Example: `ditgor-p...`

##### References

- [DocSpace API: Basic Authentication]
- [DocSpace MCP: Authentication Resolution]

## Examples

The following examples show how to use request configuration headers to
customize server behavior for specific requests.

### Authentication with API Key

This configuration uses an API key for authentication.

```http
X-Mcp-Base-Url: https://your-instance.onlyoffice.com/
X-Mcp-Api-Key: sk-a499e...
```

### Custom Tool Selection

This configuration restricts the available tools to a specific set.

```http
X-Mcp-Toolsets: files
X-Mcp-Enabled-Tools: get_all_people
X-Mcp-Disabled-Tools: delete_file,delete_folder
```

<!-- Footnotes -->

[DocSpace API: API Keys]: https://api.onlyoffice.com/docspace/api-backend/get-started/authentication/api-keys/
[DocSpace API: OAuth]: https://api.onlyoffice.com/docspace/api-backend/get-started/authentication/oauth2/
[DocSpace API: Basic Authentication]: https://api.onlyoffice.com/docspace/api-backend/get-started/authentication/basic-authentication/
[DocSpace API: Personal Access Tokens]: https://api.onlyoffice.com/docspace/api-backend/get-started/authentication/personal-access-tokens/

[DocSpace MCP: Toolsets]: ../features/tools.md#toolsets
[DocSpace MCP: Tools]: ../features/tools.md#regular-tools
[DocSpace MCP: Meta Tools]: ../features/tools.md#meta-tools
[DocSpace MCP: Authentication Resolution]: ./authentication-resolution.md
[DocSpace MCP: Tools Resolution]: ./tools-resolution.md

[`X-Mcp-Toolsets`]: #x-mcp-toolsets
[`X-Mcp-Enabled-Tools`]: #x-mcp-enabled-tools
[`X-Mcp-Disabled-Tools`]: #x-mcp-disabled-tools
[`Authorization`]: #authorization
[`X-Mcp-Api-Key`]: #x-mcp-api-key
[`X-Mcp-Auth-Token`]: #x-mcp-auth-token
[`X-Mcp-Username`]: #x-mcp-username
[`X-Mcp-Password`]: #x-mcp-password
