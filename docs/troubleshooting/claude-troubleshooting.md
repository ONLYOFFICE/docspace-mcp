# Resolving issues with Claude

The following issues can occur with Claude Web and Claude Desktop clients.

## Claude Web

### You cannot add a custom connector

The **Add custom connector** option is unavailable. On the Claude Free plan, you can add only one custom connector. To fix:

- Remove the existing custom connector: click its name in the **Connectors** list, click **⋮**, and select **Remove**.
- Alternatively, upgrade your Claude plan at [claude.ai/upgrade](https://claude.ai/upgrade). If you are on a Team or Enterprise plan, contact your workspace administrator to confirm that custom connectors are enabled for your organization.

### The connector was added but the Connect button is missing or inactive

The connector URL may have been entered incorrectly, or the MCP server is temporarily unavailable. Try the following solutions:

- Click the connector name to open its settings and verify the URL is exactly `https://mcp.onlyoffice.com/mcp`.
- Delete the connector (click its name, click **⋮**, and select **Remove**) and add it again.
- Check the ONLYOFFICE Apps MCP server status or contact your ONLYOFFICE Apps administrator.

### Authentication succeeds, but Claude cannot read or modify ONLYOFFICE Apps files

The granted OAuth permissions may not include the required scopes, or the permissions were accidentally denied. Try any of these fixes:

- Go to **Settings → Connectors**, click the connector name, click **Disconnect**, and then click **Connect** again.
- During the OAuth flow, click **Allow** when prompted to grant access to your ONLYOFFICE Apps data.
- Check your ONLYOFFICE Apps account permissions with your administrator.

### The connector shows as Connected, but ONLYOFFICE Apps tools are not available in Claude

The session may have expired, or the connector needs to be refreshed.

- Go to **Settings → Connectors**, click the connector name, click **Disconnect**, and then click **Connect** again.
- Sign out of Claude Web and sign back in.
- If the issue persists, delete the connector and retry adding the connection.

## Claude Desktop

### The MCP Extension does not appear after installation

After installing the MCP bundle, the extension is not listed under **Extensions** due to any of the following:

- **Node.js settings.** Claude Desktop uses its built-in Node.js when the system Node.js is missing or outdated. Make sure **Use built-in Node.js for MCP** is turned on in **Settings** → **Extensions** → **Advanced settings**.
- **The bundle file is corrupted or from an outdated release.** Re-download the latest MCP bundle from [GitHub Releases](https://github.com/ONLYOFFICE/docspace-mcp/releases).
- **Claude Desktop needs to be restarted.** Fully quit Claude Desktop (not just close the window) and relaunch it after installation.

### Extension tools return "No authentication method"

The extension is installed and enabled, but tool calls fail with the `No authentication method` error. The extension settings are empty. To fix:

1. Navigate to **Settings** → **Extensions** and click the ONLYOFFICE Apps extension.
2. Click **Configure**.
3. Fill in **Base URL** and **API Key**, and then click **Save**.

### Claude Desktop does not reflect config changes

After editing `claude_desktop_config.json`, the changes seem to have no effect. To fix:

- Fully quit the application and relaunch it as Claude Desktop reads the configuration only at startup. On macOS, use **Quit Claude** from the menu bar icon rather than simply closing the window. On Windows, right-click the Claude icon in the system tray and select **Exit**.
