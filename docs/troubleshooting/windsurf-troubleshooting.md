# Troubleshooting issues with Devin Desktop MCP client

The following issues can occur when connecting the ONLYOFFICE Apps MCP server to the Devin Desktop client (formerly Windsurf).

## The MCP server does not appear in Devin Desktop after saving the configuration

This may be due to any of the following reasons:

- **JSON syntax error.** Verify that the configuration file is valid JSON as missing commas, unclosed brackets, or extra trailing commas will prevent the file from being parsed. Use a JSON validator (e.g., [jsonlint.com](https://jsonlint.com)) to check the syntax.
- **The server was not reloaded.** After saving the configuration file, check the server in **Devin Customizations** → **MCPs** → **Installed**. If the server still uses the old settings, click **onlyoffice-apps** to open the server page, click **Uninstall**, and then add the record again.
- **Missing or misplaced `mcpServers` key.** Make sure the `onlyoffice-apps` record is nested directly inside the `mcpServers` object, not at the root level of the file.

## Changes to the configuration file are not applied

These changes may not be reflected due to any of the following:

- **File was saved in the wrong location.** Devin Desktop reads the `mcp_config.json` file from `%APPDATA%\devin` on Windows and from `~/.config/devin` on macOS and Linux. To open the correct file, select **Devin: Devin MCP Registry** in Command Palette, navigate to **MCPs** → **Available**, and click **Add custom MCP**.
- **The configuration is in the old Windsurf location.** If you configured the server in Windsurf, the configuration may still be in the `~/.codeium` folder. Select **Devin: Migrate MCP Config** in Command Palette to move it to the new location.
- **Multiple configuration files conflict.** If both a user-level and a workspace-level configuration exist, the workspace-level file may override the user-level one. Check for a project-level configuration in your project folder.

## The server shows "Connection failed"

To see the error details, click **onlyoffice-apps** in **Devin Customizations** → **MCPs** → **Installed** to open the server page, and then click **View logs**. The logs open in the **Output** panel in the **MCP** channel.
