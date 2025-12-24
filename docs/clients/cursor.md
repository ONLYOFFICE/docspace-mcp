# Cursor

This document describes how to connect to the DocSpace MCP server using Cursor.

## Contents

- [HTTP](#http)
- [Command](#command)
- [References](#references)

## HTTP

Connect to the MCP server running remotely using Streamable-HTTP transport. This
is the preferred connection method.

1. Open Cursor;
2. Bring up Command Palette;
3. Select "View: Open MCP Settings";
4. Click "Add Custom MCP";
5. Add a new record to the `mcpServers` section:
   ```json
   {
   	"mcpServers": {
   		"onlyoffice-docspace": {
   			"type": "http",
   			"url": "https://mcp.onlyoffice.com/mcp"
   		}
   	}
   }
   ```
6. Save the file;
7. Navigate back to "MCP Settings";
8. Click "Connect" next to the newly added MCP server;
9. Complete the OAuth authentication process.

## Command

Connect to the locally running MCP server using stdio transport.

Ensure [Docker] is installed on your system.

1. Open Cursor;
2. Bring up Command Palette;
3. Select "View: Open MCP Settings";
4. Click "Add Custom MCP";
5. Add a new record to the `mcpServers` section:
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
6. Save the file.

## References

- [Cursor: Keyboard Shortcuts]
- [Cursor: Model Context Protocol (MCP)]
- [Docker MCP: Distribution]
- [Docker MCP: Installation]
- [Docker MCP: Configuration]

<!-- Definitions -->

[Docker]: https://www.docker.com/

[Cursor: Keyboard Shortcuts]: https://cursor.com/docs/configuration/kbd
[Cursor: Model Context Protocol (MCP)]: https://cursor.com/docs/context/mcp

[Docker MCP: Configuration]: ../configuration/README.md
[Docker MCP: Distribution]: ../distribution/README.md
[Docker MCP: Installation]: ../installation/README.md
