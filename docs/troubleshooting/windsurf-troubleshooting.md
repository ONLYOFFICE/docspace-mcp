# Troubleshooting issues with Windsurf MCP client

The following issues can occur when connecting the DocSpace MCP server to the Windsurf client.

## The MCP server does not appear in Windsurf after saving the configuration

This may be due to any of the following reasons:

- **JSON syntax error.** Verify that the configuration file is valid JSON as missing commas, unclosed brackets, or extra trailing commas will prevent the file from being parsed. Use a JSON validator (e.g., [jsonlint.com](https://jsonlint.com)) to check the syntax.
- **The server was not reloaded.** After saving the configuration file, restart Windsurf or reload the MCP server list via **Open MCP Marketplace**.
- **Missing or misplaced `mcpServers` key.** Make sure the `onlyoffice-docspace` record is nested directly inside the `mcpServers` object, not at the root level of the file.

## Changes to the configuration file are not applied

These changes may not be reflected due to any of the following:

- **File was saved in the wrong location.** Confirm that you edited the Windsurf User Settings file, not a project-level settings file. Use **Open Windsurf User Settings** from the Command Palette to open the correct file.
- **Multiple configuration files conflict.** If both a user-level and a workspace-level configuration exist, the workspace-level file may override the user-level one. Check for an `.windsurf` or similar directory in your project root.
