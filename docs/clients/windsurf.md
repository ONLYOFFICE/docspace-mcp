# Windsurf

This document describes how to connect to the DocSpace MCP server using
Windsurf.

## Contents

- [HTTP](#http)
- [Command](#command)
- [References](#references)

## HTTP

Connect to the MCP server running remotely using Streamable-HTTP transport. This
is the preferred connection method.

1. Open Windsurf;
2. Bring up Command Palette;
3. Select "Open Windsurf User Settings";
4. Navigate to Cascade;
5. Click "Open MCP Marketplace";
6. Click "Settings";
7. Add a new record to the `mcpServers` section:
   ```json
   {
   	"mcpServers": {
   		"onlyoffice-docspace": {
   			"serverUrl": "https://mcp.onlyoffice.com/mcp"
   		}
   	}
   }
   ```
8. Save the file;
9. Complete the OAuth authentication process.

## Command

Connect to the locally running MCP server using stdio transport.

Ensure [Docker] is installed on your system.

1. Open Windsurf;
2. Bring up Command Palette;
3. Select "Open Windsurf User Settings";
4. Navigate to Cascade;
5. Click "Open MCP Marketplace";
6. Click "Settings";
7. Add a new record to the `mcpServers` section:
   ```json
   {
   	"mcpServers": {
   		"onlyoffice-docspace": {
   			"command": "docker",
   			"args": [
   				"run",
   				"--interactive",
   				"--rm",
   				"--env",
   				"DOCSPACE_BASE_URL",
   				"--env",
   				"DOCSPACE_API_KEY",
   				"onlyoffice/docspace-mcp"
   			],
   			"env": {
   				"DOCSPACE_BASE_URL": "https://your-instance.onlyoffice.com",
   				"DOCSPACE_API_KEY": "your-api-key"
   			}
   		}
   	}
   }
   ```
8. Save the file.

## References

- [Windsurf: Open Command Palette]
- [Windsurf: Model Context Protocol (MCP)]
- [Docker MCP: Distribution]
- [Docker MCP: Installation]
- [Docker MCP: Configuration]

<!-- Definitions -->

[Docker]: https://www.docker.com/

[Windsurf: Open Command Palette]: https://docs.windsurf.com/windsurf/getting-started#open-command-palette
[Windsurf: Model Context Protocol (MCP)]: https://docs.windsurf.com/windsurf/cascade/mcp

[Docker MCP: Configuration]: ../configuration/README.md
[Docker MCP: Distribution]: ../distribution/README.md
[Docker MCP: Installation]: ../installation/README.md
