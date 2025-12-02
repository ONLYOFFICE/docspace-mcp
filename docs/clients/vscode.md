# Visual Studio Code

This document describes how to connect to the DocSpace MCP server using Visual
Studio Code.

## Contents

- [HTTP](#http)
- [Command](#command)
- [References](#references)

## HTTP

Connect to the MCP server running remotely using Streamable-HTTP transport. This
is the preferred method of connection.

1. Open Visual Studio Code;
2. Bring up Command Pallette;
3. Select "MCP: Open User Configuration";
4. Add a new record to the `servers` section:
   ```json
   {
   	"servers": {
   		"onlyoffice-docspace": {
   			"type": "http",
   			"url": "https://mcp.onlyoffice.com/mcp"
   		}
   	}
   }
   ```
5. Bring up Command Pallette;
6. Select "MCP: List Servers";
7. Select "onlyoffice-docspace";
8. Select "Start Server";
9. Complete the OAuth authentication process.

## Command

Connect to a locally running the MCP server using stdio transport.

Ensure [Docker] is installed on your system.

1. Open Visual Studio Code;
2. Bring up Command Pallette;
3. Select "MCP: Open User Configuration";
4. Add a new record to the `servers` section:
   ```json
   {
   	"servers": {
   		"onlyoffice-docspace": {
   			"command": "docker",
   			"args": ["run", "onlyoffice/docspace-mcp", "--interactive", "--rm", "--env", "DOCSPACE_BASE_URL", "--env", "DOCSPACE_API_KEY"],
   			"env": {
   				"DOCSPACE_BASE_URL": "https://your-instance.onlyoffice.com",
   				"DOCSPACE_API_KEY": "your-api-key"
   			}
   		}
   	}
   }
   ```
5. Bring up Command Pallette;
6. Select "MCP: List Servers";
7. Select "onlyoffice-docspace";
8. Select "Start Server".

## References

- [Visual Studio Code: Command Palette]
- [Visual Studio Code: Use MCP Servers]
- [Docker MCP: Distribution]
- [Docker MCP: Installation]
- [Docker MCP: Configuration]

<!-- Definitions -->

[Docker]: https://www.docker.com/

[Visual Studio Code: Use MCP Servers]: https://code.visualstudio.com/docs/copilot/customization/mcp-servers
[Visual Studio Code: Command Palette]: https://code.visualstudio.com/docs/getstarted/userinterface/#_command-palette

[Docker MCP: Configuration]: ../configuration/README.md
[Docker MCP: Distribution]: ../distribution/README.md
[Docker MCP: Installation]: ../installation/README.md
