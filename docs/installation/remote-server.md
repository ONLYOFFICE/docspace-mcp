# Remote Server

This document describes how to connect to the DocSpace MCP server running on
a remote machine.

## Contents

- [Quick Install](#quick-install)
- [Public Instance](#public-instance)
- [Examples](#examples)
- [References](#references)

## Public Instance

The public instance is available at https://mcp.onlyoffice.com/mcp for clients
that support modern Streamable HTTP transport and at
https://mcp.onlyoffice.com/sse for clients that support only the legacy SSE
transport. Prefer to use the Streamable HTTP transport whenever possible.

The public instance supports authentication using OAuth, API key, Personal
Access Token (PAT), username/password pair, or raw `Authorization` header.
Prefer to use OAuth authentication whenever possible.

The public instance provides access to all available tools by default. Tool
selection can be customized using query parameters or custom headers. However,
prefer to use the MCP client interface for tool configuration when supported.

## Examples

The following examples demonstrate different authentication methods for
connecting to the public instance.

### OAuth with Public App

Connect using the public OAuth application without custom credentials.

```http
https://mcp.onlyoffice.com/mcp
```

### OAuth with Custom App

Connect using custom OAuth client ID and client secret.

```http
https://mcp.onlyoffice.com/mcp
```

```
OAuth Client ID: 68cf0a49...
OAuth Client Secret: vEHLGi5...
```

### API Key with Headers

Connect using API key and base URL configured via custom headers.

```http
https://mcp.onlyoffice.com/mcp
```

```http
X-Mcp-Base-Url: https://your-instance.onlyoffice.com/
X-Mcp-Api-Key: sk-a499e...
```

### API Key with Authorization Header

Connect using API key in `Authorization` header and base URL in query parameter.

```http
https://mcp.onlyoffice.com/mcp?base_url=https://your-instance.onlyoffice.com
```

```http
Authorization: Bearer sk-a499e...
```

### Username and Password in URL

Connect using URL-encoded credentials and base URL in query parameter.

```http
https://henry.milton%40onlyoffice.com:ditgor-p...@mcp.onlyoffice.com/mcp?base_url=https://your-instance.onlyoffice.com/
```

## References

- [MCP: Connect to Remote MCP Servers]
- [MCP: Example Clients]
- [Docker MCP: Request Configuration]

<!-- Definitions -->

[MCP: Connect to Remote MCP Servers]: https://modelcontextprotocol.io/docs/tutorials/use-remote-mcp-server
[MCP: Example Clients]: https://modelcontextprotocol.io/clients

[Docker MCP: Request Configuration]: ../configuration/request-configuration.md
