# Resolving issues with VS Code client

The following issues can occur when connecting the ONLYOFFICE Apps MCP server to VS Code.

## The MCP server does not appear in the list

The configuration file may contain a syntax error, or the `servers` section is missing. Follow these steps to fix:

1. Open Command Palette and select **MCP: Open User Configuration**.
2. Validate the JSON structure. Make sure the `onlyoffice-apps` entry is nested inside the `servers` object and all brackets are properly closed.
3. Save the file and try **MCP: List Servers** again.

## Server status shows "Error" or fails to start

**Remote server**: Network connectivity issue or the remote MCP server is temporarily unavailable.

**Local:** Docker is not running, or the `onlyoffice/docspace-mcp` image has not been pulled yet.

To fix this:

- **Remote:** Check your internet connection. Verify that `https://mcp.onlyoffice.com/mcp` is reachable from your browser. If the issue persists, try restarting VS Code.
- **Local:** Make sure Docker Desktop is running. Pull the image manually by running:
  ```bash
  docker pull onlyoffice/docspace-mcp
  ```
  Then click **Restart** above the `onlyoffice-apps` record in the `mcp.json` file.

To see the server log, click **More...** above the `onlyoffice-apps` record and select **Show Output**.

## Authentication succeeds, but the server immediately disconnects

The OAuth token was not saved correctly, or the session expired before the handshake completed. Try this fix:

1. Click **More...** above the `onlyoffice-apps` record in the `mcp.json` file and select **Sign Out (MCP)**.
2. Click **Start** above the record and complete the authentication process again.
3. If the problem repeats, sign out of your ONLYOFFICE Apps account in the browser, clear cookies for `mcp.onlyoffice.com`, and start the authentication flow again.

## The local server cannot connect to the ONLYOFFICE Apps instance

This happens when the `DOCSPACE_BASE_URL` value is incorrect or the API key is invalid/expired. To fix:

- Verify that the URL is correct and accessible: open it in a browser and confirm the ONLYOFFICE Apps login page loads.
- Create a new API key in ONLYOFFICE Apps **Developer Tools** → **API keys** and update the value in the configuration file.
- Ensure the URL does not have a trailing slash (e.g., use `https://your-instance.onlyoffice.com`, not `https://your-instance.onlyoffice.com/`).

## Tool calls fail with a configuration error

The server status shows **Running** and lists the tools, but every tool call returns an error, such as `No authentication method` or `No API base URL`. A required environment variable (`DOCSPACE_BASE_URL` or `DOCSPACE_API_KEY`) is missing or empty. In this case, the server does not stop: it starts and reports the configuration error on each tool call.

To fix:

- Check that both variables are set in the `env` block of your configuration and that the values are not empty strings or placeholder text.
- Save the file and click **Restart** above the `onlyoffice-apps` record.
- To see the error details, click **More...** above the record and select **Show Output**.

## Tools are not available in GitHub Copilot Chat after connecting

VS Code did not register the MCP tools yet, or the MCP extension requires a reload. To fix:

1. Make sure the server status in **MCP: List Servers** shows **Running**.
2. Open a new Copilot Chat window — tools are registered per chat session.
3. If tools are still missing, reload VS Code (`Developer: Reload Window` in Command Palette) and start the server again.
