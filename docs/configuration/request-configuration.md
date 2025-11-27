# Request Configuration

This document describes how to configure the DocSpace MCP server behavior on the
request level using query parameters and custom headers. Request configuration
is only available for HTTP-like transports.

## Contents

- [Query Options](#query-options)
  - [MCP Options](#mcp-options)
    - [dynamic](#dynamic)
    - [toolsets](#toolsets)
    - [enabled_tools](#enabled_tools)
    - [disabled_tools](#disabled_tools)
  - [API Options](#api-options-1)
    - [base_url](#base_url)
- [Header Options](#header-options)
  - [MCP Options](#mcp-options-1)
    - [X-Mcp-Dynamic](#x-mcp-dynamic)
    - [X-Mcp-Toolsets](#x-mcp-toolsets)
    - [X-Mcp-Enabled-Tools](#x-mcp-enabled-tools)
    - [X-Mcp-Disabled-Tools](#x-mcp-disabled-tools)
  - [API Options](#api-options-2)
    - [X-Mcp-Base-Url](#x-mcp-base-url)
    - [Authorization](#authorization)
    - [X-Mcp-Api-Key](#x-mcp-api-key)
    - [X-Mcp-Auth-Token](#x-mcp-auth-token)
    - [X-Mcp-Username](#x-mcp-username)
    - [X-Mcp-Password](#x-mcp-password)
- [Examples](#examples)
  - [Authentication with API Key](#authentication-with-api-key)
  - [Custom Tool Selection](#custom-tool-selection)

## Query Options

The following options can be configured using query parameters in the request
URL.

Query parameters are only available if the MCP server is configured to accept
configuration via query parameters.

### MCP Options

The following options are used to configure the behavior of the MCP server.

#### dynamic

The flag that indicates whether the MCP server should use meta tools.

This option is complementary to [`toolsets`], [`enabled_tools`], and
[`disabled_tools`].

This option is mutually exclusive with [`X-Mcp-Dynamic`].

##### Signature

- Type: boolean
- Variants (true): `yes`, `y`, `true`, `1`
- Variants (false): `no`, `n`, `false`, `0`
- Attributes: trimmable, case-insensitive

##### References

- [DocSpace MCP: Meta Tools]

#### toolsets

The list of toolsets to enable for the MCP server.

The available list of toolsets for this options depends on the MCP server global
configuration.

This option is mutually exclusive with [`X-Mcp-Toolsets`].

##### Signature

- Type: comma-separated list of toolset names
- Attributes: trimmable, case-insensitive
- Example: `files,people`

##### References

- [DocSpace MCP: Toolsets]
- [DocSpace MCP: Tools Resolution]

#### enabled_tools

The list of tools to enable for the MCP server.

The available list of tools for this options depends on the MCP server global
configuration.

This option is mutually exclusive with [`X-Mcp-Enabled-Tools`].

##### Signature

- Type: comma-separated list of tool names
- Attributes: trimmable, case-insensitive
- Example: `get_file,get_all_people`

##### References

- [DocSpace MCP: Tools]
- [DocSpace MCP: Tools Resolution]

#### disabled_tools

The list of tools to disable for the MCP server.

The available list of tools for this options depends on the MCP server global
configuration.

This option is mutually exclusive with [`X-Mcp-Disabled-Tools`].

##### Signature

- Type: comma-separated list of tool names
- Attributes: trimmable, case-insensitive
- Example: `get_file,get_all_people`

##### References

- [DocSpace MCP: Tools]
- [DocSpace MCP: Tools Resolution]

### API Options

The following options are used to configure the behavior for API requests.

#### base_url

The base URL of the DocSpace instance for API requests.

The base URL must use HTTP or HTTPS scheme without search parameters or hash
fragments.

This option is mutually exclusive with [`X-Mcp-Base-Url`].

##### Signature

- Type: url
- Attributes: trimmable
- Example: `https://your-instance.onlyoffice.com/`

## Header Options

The following options can be configured using custom HTTP headers.

HTTP headers are only available if the MCP server is configured to accept
configuration via HTTP headers.

### MCP Options

The following options are used to configure the behavior of the MCP server.

#### X-Mcp-Dynamic

The flag that indicates whether the MCP server should use meta tools.

This option is complementary to [`X-Mcp-Toolsets`], [`X-Mcp-Enabled-Tools`], and
[`X-Mcp-Disabled-Tools`].

This option is mutually exclusive with [`dynamic`].

##### Signature

- Type: boolean
- Variants (true): `yes`, `y`, `true`, `1`
- Variants (false): `no`, `n`, `false`, `0`
- Attributes: trimmable, case-insensitive

##### References

- [DocSpace MCP: Meta Tools]

#### X-Mcp-Toolsets

The list of toolsets to enable for the DocSpace MCP server.

The available list of toolsets for this options depends on the MCP server global
configuration.

This option is mutually exclusive with [`toolsets`].

##### Signature

- Type: comma-separated list of toolset names
- Attributes: trimmable, case-insensitive
- Example: `files,people`

##### References

- [DocSpace MCP: Toolsets]
- [DocSpace MCP: Tools Resolution]

#### X-Mcp-Enabled-Tools

The list of tools to enable for the MCP server.

The available list of tools for this options depends on the MCP server global
configuration.

This option is mutually exclusive with [`enabled_tools`].

##### Signature

- Type: comma-separated list of tool names
- Attributes: trimmable, case-insensitive
- Example: `get_file,get_all_people`

##### References

- [DocSpace MCP: Tools]
- [DocSpace MCP: Tools Resolution]

#### X-Mcp-Disabled-Tools

The list of tools to disable for the MCP server.

The available list of tools for this options depends on the MCP server global
configuration.

This option is mutually exclusive with [`disabled_tools`].

##### Signature

- Type: comma-separated list of tool names
- Attributes: trimmable, case-insensitive
- Example: `get_file,get_all_people`

##### References

- [DocSpace MCP: Tools]
- [DocSpace MCP: Tools Resolution]

### API Options

The following options are used to configure the behavior for API requests.

#### X-Mcp-Base-Url

The base URL of the DocSpace instance for API requests.

The base URL must use HTTP or HTTPS scheme without search parameters or hash
fragments.

This option is required if either [`Authorization`], [`X-Mcp-Api-Key`],
[`X-Mcp-Auth-Token`], or the [`X-Mcp-Username`]/[`X-Mcp-Password`] pair is set.

This option is mutually exclusive with [`base_url`].

##### Signature

- Type: url
- Attributes: trimmable
- Example: `https://your-instance.onlyoffice.com/`

#### Authorization

The raw value to include in the `Authorization` header for API requests.

This option is available only if the MCP server is configured to accept the
`Authorization` header in incoming requests.

This option is required if the MCP server is configured without authentication,
and neither [`X-Mcp-Api-Key`], [`X-Mcp-Auth-Token`], nor the
[`X-Mcp-Username`]/[`X-Mcp-Password`] pair is set, and the OAuth flow is not
initialized.

This option is mutually exclusive with [`X-Mcp-Api-Key`], [`X-Mcp-Auth-Token`],
the [`X-Mcp-Username`]/[`X-Mcp-Password`] pair, and the OAuth flow.

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

The API key for accessing the API.

This option is required if the MCP server is configured without authentication,
and neither [`Authorization`], [`X-Mcp-Auth-Token`], nor the
[`X-Mcp-Username`]/[`X-Mcp-Password`] pair is set, and the OAuth flow is not
initialized.

This option is mutually exclusive with [`Authorization`], [`X-Mcp-Auth-Token`],
the [`X-Mcp-Username`]/[`X-Mcp-Password`] pair, and the OAuth flow.

##### Signature

- Type: string
- Attributes: sensitive, trimmable
- Example: `sk-a499e...`

##### References

- [DocSpace API: API Keys]
- [DocSpace MCP: Authentication Resolution]

#### X-Mcp-Auth-Token

The Personal Access Token (PAT) for accessing the API.

This option is required if the MCP server is configured without authentication,
and neither [`Authorization`], [`X-Mcp-Api-Key`], nor the
[`X-Mcp-Username`]/[`X-Mcp-Password`] pair is set, and the OAuth flow is not
initialized.

This option is mutually exclusive with [`Authorization`], [`X-Mcp-Api-Key`],
the [`X-Mcp-Username`]/[`X-Mcp-Password`] pair, and the OAuth flow.

##### Signature

- Type: string
- Attributes: sensitive, trimmable
- Example: `Fe4Hrgl6...`

##### References

- [DocSpace API: Personal Access Tokens]
- [DocSpace MCP: Authentication Resolution]

#### X-Mcp-Username

The username for accessing the API using basic authentication.

This option is used in conjunction with [`X-Mcp-Password`].

This option is required if the MCP server is configured without authentication,
and neither [`Authorization`], [`X-Mcp-Api-Key`], nor [`X-Mcp-Auth-Token`] is
set, and the OAuth flow is not initialized.

This option is mutually exclusive with [`Authorization`], [`X-Mcp-Api-Key`],
[`X-Mcp-Auth-Token`], and the OAuth flow.

##### Signature

- Type: string
- Attributes: sensitive, trimmable
- Example: `henry.milton@onlyoffice.com`

##### References

- [DocSpace API: Basic Authentication]
- [DocSpace MCP: Authentication Resolution]

#### X-Mcp-Password

The password for accessing the API using basic authentication.

This option is used in conjunction with [`X-Mcp-Username`].

This option is required if the MCP server is configured without authentication,
and neither [`Authorization`], [`X-Mcp-Api-Key`], nor [`X-Mcp-Auth-Token`] is
set, and the OAuth flow is not initialized.

This option is mutually exclusive with [`Authorization`], [`X-Mcp-Api-Key`],
[`X-Mcp-Auth-Token`], and the OAuth flow.

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

<!-- Definitions -->

[DocSpace API: API Keys]: https://api.onlyoffice.com/docspace/api-backend/get-started/authentication/api-keys/
[DocSpace API: Basic Authentication]: https://api.onlyoffice.com/docspace/api-backend/get-started/authentication/basic-authentication/
[DocSpace API: Personal Access Tokens]: https://api.onlyoffice.com/docspace/api-backend/get-started/authentication/personal-access-tokens/

[DocSpace MCP: Toolsets]: ../features/tools.md#toolsets
[DocSpace MCP: Tools]: ../features/tools.md#regular-tools
[DocSpace MCP: Meta Tools]: ../features/tools.md#meta-tools
[DocSpace MCP: Authentication Resolution]: ./authentication-resolution.md
[DocSpace MCP: Tools Resolution]: ./tools-resolution.md

[`dynamic`]: #dynamic
[`toolsets`]: #toolsets
[`enabled_tools`]: #enabled_tools
[`disabled_tools`]: #disabled_tools
[`base_url`]: #base_url
[`X-Mcp-Dynamic`]: #x-mcp-dynamic
[`X-Mcp-Toolsets`]: #x-mcp-toolsets
[`X-Mcp-Enabled-Tools`]: #x-mcp-enabled-tools
[`X-Mcp-Disabled-Tools`]: #x-mcp-disabled-tools
[`X-Mcp-Base-Url`]: #x-mcp-base-url
[`Authorization`]: #authorization
[`X-Mcp-Api-Key`]: #x-mcp-api-key
[`X-Mcp-Auth-Token`]: #x-mcp-auth-token
[`X-Mcp-Username`]: #x-mcp-username
[`X-Mcp-Password`]: #x-mcp-password
