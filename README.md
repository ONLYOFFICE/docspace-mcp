# ONLYOFFICE DocSpace MCP Server

[Model Context Protocol] (MCP) is a standardized protocol for managing context
between large language models (LLMs) and external systems. This repository
provides an MCP server for [ONLYOFFICE DocSpace].

> [!WARNING]
>
> This DocSpace MCP server is currently in **preview** state. While functional,
> it may undergo breaking changes, have incomplete features, or contain bugs.
> Use with caution in production environments and expect potential updates that
> could affect compatibility.

```json
{
	"mcpServers": {
		"onlyoffice-docspace": {
			"command": "docker",
			"args": ["run", "--interactive", "--rm", "--env", "DOCSPACE_BASE_URL", "--env", "DOCSPACE_API_KEY", "onlyoffice/docspace-mcp"],
			"env": {
				"DOCSPACE_BASE_URL": "https://your-instance.onlyoffice.com",
				"DOCSPACE_API_KEY": "your-api-key"
			}
		}
	}
}
```

## Features

- **Tools with granular control** - Access to tools organized into logical
  toolsets with fine-grained enable/disable capabilities and meta tools.
- **Multiple transport protocols** - Support for stdio, SSE, and Streamable HTTP
  transports.
- **Different authentication methods** - Supports OAuth, API keys, Personal
  Access Tokens, and Basic authentication.
- **Request-level configuration** - Configure authentication and tool selection
  during session initialization using custom HTTP headers.
- **Various distribution formats** - Available as Docker image, Docker MCP
  Server, MCP bundle, and Node.js application.

## Documentation

The documentation is available in the [docs] directory.

## License

The DocSpace MCP server is distributed under the Apache-2.0 license found in
the [LICENSE] file.

<!-- Footnotes -->

[docs]: https://github.com/ONLYOFFICE/docspace-mcp/tree/v3.1.0/docs
[LICENSE]: https://github.com/onlyoffice/docspace-mcp/blob/v3.1.0/LICENSE

[Model Context Protocol]: https://modelcontextprotocol.io/
[ONLYOFFICE DocSpace]: https://www.onlyoffice.com/docspace.aspx
