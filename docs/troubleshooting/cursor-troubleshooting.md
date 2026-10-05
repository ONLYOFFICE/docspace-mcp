# Troubleshooting issues with Cursor client

The following issues can occur when connecting the ONLYOFFICE Apps MCP server to the Cursor client.

## Docker image fails to pull

Ensure Docker is running and you have internet access. Try pulling the image manually to see the full error message:

```bash
docker pull onlyoffice/docspace-mcp
```

If you are behind a corporate proxy, configure Docker to use it: **Docker Desktop → Settings → Resources → Proxies**.

## MCP server starts but Cursor does not list any tools

Run the container manually to check for startup errors:

```bash
docker run --interactive --rm \
  --env DOCSPACE_BASE_URL=https://your-instance.onlyoffice.com \
  --env DOCSPACE_API_KEY=your-api-key \
  onlyoffice/docspace-mcp
```

Review the output for error messages and fix the reported issue before reconnecting in Cursor.

You can also check the server logs in Cursor. Switch to the IDE view, bring up Command Palette, select **Output: Show Output Channels**, and then select **MCP: user-onlyoffice-apps**.

## Permission denied when running Docker

On Linux, your user account may not be in the `docker` group. Add your user and restart the session:

```bash
sudo usermod -aG docker $USER
```

## Remote server tools stop working after authentication

If the remote server was connected but its tools stop working, for example, because the session has expired, sign in again:

1. Bring up Command Palette and select **Open MCPs**.
2. Click **onlyoffice-apps**.
3. In the **Environments** section, click **Logout**.
4. Click **Authenticate**, which appears in the same section, and complete the OAuth authentication process again.
