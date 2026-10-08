# Common issues

The following issues can occur with any MCP client when connecting to or using the ONLYOFFICE Apps MCP server.

## Parsing errors

If an error occurs during global configuration parsing, the ONLYOFFICE Apps MCP server will automatically fall back to using the stdio transport and defer the
configuration error until tool execution:

1. Encounter an error while parsing global configuration.
2. Start successfully using stdio transport.
3. Respond normally to MCP protocol requests.
4. Return the original configuration parsing error when any tool is called.

This fallback behavior is implemented to ensure compatibility with the Docker
MCP Registry, which requires servers to start successfully even with
configuration issues.

## Connection fails after entering the server URL

The MCP server URL may be unreachable due to network restrictions, a VPN, or a typo in the URL. Try any of these solutions:

- Ensure the URL is entered correctly: `https://mcp.onlyoffice.com/mcp`.
- Check that your network or firewall does not block access to `mcp.onlyoffice.com`.
- If you are using a VPN, try disabling it and reconnecting.
- Open the URL directly in a browser to verify it is reachable.

## OAuth authentication fails or the browser does not open

Sometimes OAuth authentication fails or the browser fails to open to authenticate the ONLYOFFICE Apps MCP server - MCP client connection. This may be due to any of these reasons:

- **No default browser configured.** The client opens the OAuth page in the system default browser. Ensure a default browser is set in your OS settings.
- **The MCP server URL is incorrect.** Verify that the URL you entered is correct with no trailing slash issues or typos.
- **Pop-ups are blocked.** If the authentication page does not appear, check that your browser is not blocking pop-ups. The sign-in window opens `mcp.onlyoffice.com` and then redirects to `oauth.onlyoffice.com`, so allow both domains.
- **The browser did not return you to the client.** After you allow access, the browser asks to open your MCP client (for example, **Open Cursor**, **Open Visual Studio Code**, or **Open Claude**). Confirm this prompt. If you click **Cancel**, the authentication is not completed.
- **Session expired or token revoked.** Delete the existing `onlyoffice-apps` entry, re-add it, and repeat the authentication process.
- **Corporate firewall or proxy.** If your organization uses a proxy, make sure that both `mcp.onlyoffice.com` and `oauth.onlyoffice.com` are reachable. Contact your network administrator if needed.

## The API key is invalid or authentication returns a 401 error (Local MCP Server)

This signals invalid authentication credentials to access the server and may result from any of these:

- **Key copied incorrectly.** Create a new API key in ONLYOFFICE Apps **Developer Tools** → **API keys** and paste it again, making sure there are no leading or trailing whitespace characters.
- **Invalid key.** Check to confirm your API key is still valid, not revoked, and enabled (the **State** toggle is on). If the key is disabled, turn the toggle on. If it is revoked, create a new API key and update the value of `DOCSPACE_API_KEY` in the configuration file.
- **Insufficient permissions.** Ensure your ONLYOFFICE Apps account has the permissions required by the MCP server. Contact your ONLYOFFICE Apps administrator to verify your account role.

## "Sign In" fails during the OAuth process

Incorrect credentials or the ONLYOFFICE Apps account may not be activated. To fix:

- Double-check your email and password.
- Ensure your ONLYOFFICE Apps account is active and you have access to your ONLYOFFICE Apps workspace.
- If you have forgotten your password, use the **Forgot your password?** link on the ONLYOFFICE Apps sign-in page.

## "Access denied" error during OAuth

Your ONLYOFFICE Apps account does not have sufficient permissions, or the OAuth application is not authorized for your workspace.
To fix this:

1. Contact your ONLYOFFICE Apps administrator to ensure your account has the necessary access rights.
2. Ask the administrator to verify that third-party OAuth integrations are allowed on the workspace.

## "Connect" button is missing or grayed out

This usually means the configuration file contains a JSON syntax error. Verify that your MCP client configuration file (`claude_desktop_config.json` for Claude Desktop, `mcp.json` for Cursor and VS Code, or `mcp_config.json` for Devin Desktop) is valid JSON — check for missing commas, mismatched braces, or trailing commas after the last property. Use a JSON validator (e.g., [jsonlint.com](https://jsonlint.com)) to check the syntax.

## "Connection refused" or "Unable to reach ONLYOFFICE Apps instance"

Check that `DOCSPACE_BASE_URL` is correct and reachable from your machine:

```bash
curl -I https://your-instance.onlyoffice.com
```

If you are using a self-hosted ONLYOFFICE Apps instance with a self-signed SSL certificate, Docker may reject the connection. Contact your administrator to add the certificate to the Docker trust store.

## Connection drops after a period of inactivity

Streamable-HTTP connections can time out due to network or firewall settings. Reconnect the server in your MCP client. If the problem persists, consider switching to the Local MCP Server setup.

## Connector appears as connected but client still can't access ONLYOFFICE Apps

The MCP server-client connection was successful but you can't access tools or interact with ONLYOFFICE Apps because:

- **Permissions were not granted during OAuth:** Disconnect the connector, click **Connect** again, and make sure to click **Allow** on the permissions screen.
- **The ONLYOFFICE Apps account has restricted API access:** Check with your ONLYOFFICE Apps administrator that your account has the necessary permissions (at minimum, read access to rooms and files).
- **The ONLYOFFICE Apps instance is unreachable:** Verify that your ONLYOFFICE Apps workspace is accessible in a browser.

## The MCP Extension does not appear after installation

After installing the MCP bundle, the extension is not listed under **Extensions**. This may be due to the following:

- **Node.js settings:** Claude Desktop uses its built-in Node.js when the system Node.js is missing or outdated. Make sure **Use built-in Node.js for MCP** is turned on in **Settings** → **Extensions** → **Advanced settings**.
- **The bundle file is corrupted or from an outdated release:** Re-download the latest MCP bundle from the [latest GitHub release](https://github.com/ONLYOFFICE/docspace-mcp/releases/latest).
- **Claude Desktop needs to be restarted:** Fully quit Claude Desktop (not just close the window) and relaunch it after installation.

## Docker-based Local MCP server fails to start

After editing the MCP client configuration file (`claude_desktop_config.json` for Claude Desktop, `mcp.json` for Cursor and VS Code, or `mcp_config.json` for Devin Desktop), the client displays an error for the `onlyoffice-apps` server, or the server is not listed among the available connections.

- **Docker is not running:** Make sure Docker Desktop (or the Docker daemon on Linux) is started before launching the client.
- **The Docker image is not pulled:** Run `docker pull onlyoffice/docspace-mcp` manually in a terminal to verify the image can be downloaded.
- **Invalid JSON in the config file:** A single misplaced comma or brace will prevent the config from loading. Validate the file with a JSON linter (e.g., [jsonlint.com](https://jsonlint.com)) before saving.
- **Incorrect environment variable values:** Double-check that `DOCSPACE_BASE_URL` includes the `https://` scheme and has no trailing slash, and that `DOCSPACE_API_KEY` is copied correctly from ONLYOFFICE Apps **Developer Tools** → **API keys** and update the `env` block in the configuration file.
- **The API key has been revoked or expired:** Create a new API key in ONLYOFFICE Apps **Developer Tools** → **API keys**, update the configuration file, and then restart the server in your MCP client.
- **Port conflict.** If another local service occupies the default port, try restarting Docker or the conflicting service.

## The MCP server is configured but no tools appear in the MCP client

The configuration is saved successfully, but the MCP client does not show any ONLYOFFICE Apps tools. Try any of these steps to fix the problem:

- Verify that the URL specified in `DOCSPACE_BASE_URL` is accessible from your machine by opening it in a browser as the ONLYOFFICE Apps instance may be unreachable.
- Restart the client after saving the configuration.
- Open the configuration again and verify the server entry is still present and correctly formatted.
- Sign in to your ONLYOFFICE Apps workspace and confirm that the account used for authentication has access to at least one room.
- Check that the Docker image was pulled successfully and the container can start. Sometimes, your Docker image may be outdated - run `docker pull onlyoffice/docspace-mcp` to update to the latest version of the image.

## Issues uploading a file to ONLYOFFICE Apps room with Claude Desktop

Receiving error messages like **Claude's response could not be fully generated** or any other issues uploading a file to your ONLYOFFICE Apps with the Claude Desktop client.

- **Issues with Claude Desktop:** Delete and reinstall Claude Desktop
- **Incorrect environment variable values:** Double-check that your `DOCSPACE_BASE_URL` is correct and that `DOCSPACE_API_KEY` is still valid and copied correctly.
