# Resolving issues with VS Code client

The following issues can occur when connecting the DocSpace MCP server to VS Code.

## The MCP server does not appear in the list

The configuration file may contain a syntax error, or the `servers` section is missing. Follow these steps to fix:

1. Open Command Palette and select **MCP: Open User Configuration**.
2. Validate the JSON structure. Make sure the `onlyoffice-docspace` entry is nested inside the `servers` object and all brackets are properly closed.
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
  Then restart the server in VS Code.

## Authentication succeeds, but the server immediately disconnects

The OAuth token was not saved correctly, or the session expired before the handshake completed. Try this fix:

1. Open Command Palette, select **MCP: List Servers**, then select **onlyoffice-docspace** and choose **Stop Server**.
2. Wait a few seconds, then select **Start Server** again and re-authenticate.
3. If the problem repeats, sign out of your DocSpace account in the browser, clear cookies for `mcp.onlyoffice.com`, and start the authentication flow again.

## The local server cannot connect to the DocSpace instance

This happens when the `DOCSPACE_BASE_URL` value is incorrect or the API key is invalid/expired. To fix:

- Verify that the URL is correct and accessible: open it in a browser and confirm the DocSpace login page loads.
- Regenerate the API key in DocSpace **Settings → Developer Tools → API Keys** and update the value in the configuration file.
- Ensure the URL does not have a trailing slash (e.g., use `https://portal.onlyoffice.com`, not `https://portal.onlyoffice.com/`).

## Docker container exits immediately after starting

A required environment variable (`DOCSPACE_BASE_URL` or `DOCSPACE_API_KEY`) is missing or empty.

To fix:

- Check that both variables are set in the `env` block of your configuration and that the values are not empty strings or placeholder text. You can verify the container startup logs by running the image manually:

```bash
docker run --rm \
  --env DOCSPACE_BASE_URL=https://your-instance.onlyoffice.com \
  --env DOCSPACE_API_KEY=your-api-key \
  onlyoffice/docspace-mcp
```

Review the output for error messages.

## Tools are not available in GitHub Copilot Chat after connecting

VS Code did not register the MCP tools yet, or the MCP extension requires a reload. To fix:

1. Make sure the server status in **MCP: List Servers** shows **Running**.
2. Open a new Copilot Chat window — tools are registered per chat session.
3. If tools are still missing, reload VS Code (`Developer: Reload Window` in Command Palette) and start the server again.
