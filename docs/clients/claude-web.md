# Claude WEB

This document describes how to connect to the DocSpace MCP server using Claude
WEB (i.e., https://claude.ai).

## Contents

- [Connector](#connector)
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

## References

- [Claude Support: Using the Connectors Directory to extend Claude's capabilities]
- [Docker MCP: Request Configuration]
- [Docker MCP: Remote Server]

<!-- Definitions -->

[Claude Support: Using the Connectors Directory to extend Claude's capabilities]: https://support.claude.com/en/articles/11724452-using-the-connectors-directory-to-extend-claude-s-capabilities

[Docker MCP: Request Configuration]: ../configuration/request-configuration.md
[Docker MCP: Remote Server]: ../installation/remote-server.md
