# Visual Studio Code

This document describes how to connect to the DocSpace MCP server using Visual
Studio Code.

## Contents

- [HTTP](#http)
- [Command](#command)
- [References](#references)

## HTTP

Connect to the MCP server running remotely using Streamable-HTTP transport. This
is the preferred connection method.

1. Open Visual Studio Code;
2. Bring up Command Palette;
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
5. Save the file;
6. Bring up Command Palette;
7. Select "MCP: List Servers";
8. Select "onlyoffice-docspace";
9. Select "Start Server";
10. Complete the OAuth authentication process.

## Command

Connect to the locally running MCP server using stdio transport.

Ensure [Docker] is installed on your system.

1. Open Visual Studio Code;
2. Bring up Command Palette;
3. Select "MCP: Open User Configuration";
4. Add a new record to the `servers` section:
   ```json
   {
   	"servers": {
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
5. Save the file;
6. Bring up Command Palette;
7. Select "MCP: List Servers";
8. Select "onlyoffice-docspace";
9. Select "Start Server".

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
