# Resolving issues with Claude

The following issues can occur with Claude Web and Claude Desktop clients.

## Claude Web

### The Connectors option is not available in Settings

The Connectors feature is only available on paid Claude plans (Pro, Team, or Enterprise). To fix:

- Upgrade your Claude plan at [claude.ai/upgrade](https://claude.ai/upgrade). If you are on a Team or Enterprise plan, contact your workspace administrator to confirm that the feature is enabled for your organization.

### The connector was added but the Connect button is missing or inactive

The connector URL may have been entered incorrectly, or the MCP server is temporarily unavailable. Try the following solutions:

- Click the connector name to open its settings and verify the URL is exactly `https://mcp.onlyoffice.com/mcp`.
- Delete the connector and add it again.
- Check the DocSpace MCP server status or contact your DocSpace administrator.

### Authentication succeeds, but Claude cannot read or modify DocSpace files

The granted OAuth permissions may not include the required scopes, or the permissions were accidentally denied. Try any of these fixes:

- Go to **Settings → Connectors**, disconnect the connector, and click **Connect** again.
- During the OAuth flow, click **Allow** when prompted to grant access to your DocSpace data.
- Check your DocSpace account permissions with your administrator.

### The connector shows as Connected, but DocSpace tools are not available in Claude

The session may have expired, or the connector needs to be refreshed.

- Go to **Settings → Connectors**, disconnect the connector, and reconnect it.
- Sign out of Claude Web and sign back in.
- If the issue persists, delete the connector and retry adding the connection.

## Claude Desktop

### The MCP Extension does not appear after installation

After installing the MCP bundle, the extension is not listed under **Extensions** due to any of the following:

- **Unsupported Node.js version.** Verify that Node.js 18 or higher is installed by running `node --version` in a terminal. Install the required version from [nodejs.org](https://nodejs.org/).
- **The bundle file is corrupted or from an outdated release.** Re-download the latest MCP bundle from [GitHub Releases](https://github.com/ONLYOFFICE/docspace-mcp/releases).
- **Claude Desktop needs to be restarted.** Fully quit Claude Desktop (not just close the window) and relaunch it after installation.

### Claude Desktop does not reflect config changes

After editing `claude_desktop_config.json`, the changes seem to have no effect. To fix:

- Fully quit the application and relaunch it as Claude Desktop reads the configuration only at startup. On macOS, use **Quit Claude** from the menu bar icon rather than simply closing the window.
