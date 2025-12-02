# Claude Desktop

This document describes how to connect to the DocSpace MCP server using Claude
Desktop.

## Contents

- [Connector](#connector)
- [Extension](#extension)
- [Local MCP](#local-mcp)
- [References](#references)

## Connector

Connect to the MCP server running remotely using Claude's Connectors. This is
the preferred method of connection.

1. Open Claude Desktop;
2. Navigate to Settings;
3. Navigate to Connectors;
4. Click "Add custom connector";
5. Enter a name (e.g., "ONLYOFFICE DocSpace MCP");
6. Enter an URL (e.g., https://mcp.onlyoffice.com/mcp);
7. Click "Add";
8. Click "Connect" next to the newly added connector;
9. Complete the OAuth authentication process.

## Extension

Connect to a locally running the MCP server using Claude's Extensions.

Ensure [Node.js] version 18 or higher is installed on your system, then download
the MCP bundle from [GitHub Releases].

1. Open Claude Desktop;
2. Navigate to Settings;
3. Navigate to Extensions;
4. Click "Advanced settings";
5. Click "Install extension";
6. Select the downloaded MCP bundle;
7. Click "Install".

## Local MCP

Connect to a locally running the MCP server using Claude's Local MCP servers.

Ensure [Docker] is installed on your system.

1. Open Claude Desktop;
2. Navigate to Settings;
3. Navigate to Developer;
4. Click "Edit config";
5. Open the configuration file in a text editor;
6. Add a new record to the `mcpServers` section:

```json
{
	"mcpServers": {
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

## References

- [Claude Support: Using the Connectors Directory to extend Claude's capabilities]
- [Claude Support: Getting Started with Local MCP Servers on Claude Desktop]
- [Docker MCP: Distribution]
- [Docker MCP: Installation]
- [Docker MCP: Configuration]

<!-- Definitions -->

[Docker]: https://www.docker.com/
[Node.js]: https://nodejs.org/

[Claude Support: Getting Started with Local MCP Servers on Claude Desktop]: https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop
[Claude Support: Using the Connectors Directory to extend Claude's capabilities]: https://support.claude.com/en/articles/11724452-using-the-connectors-directory-to-extend-claude-s-capabilities

[GitHub Releases]: https://github.com/ONLYOFFICE/docspace-mcp/releases

[Docker MCP: Configuration]: ../configuration/README.md
[Docker MCP: Distribution]: ../distribution/README.md
[Docker MCP: Installation]: ../installation/README.md
