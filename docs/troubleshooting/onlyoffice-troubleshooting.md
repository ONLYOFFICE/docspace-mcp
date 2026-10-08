# Resolving errors with the ONLYOFFICE Desktop Editors

The following issues can occur when connecting the ONLYOFFICE Desktop Editors to the ONLYOFFICE Apps MCP server.

## Docker is not found or not running

The MCP server fails to start with an error like `command not found: docker` or `Cannot connect to the Docker daemon`. To fix:

- Make sure Docker Desktop is installed. Download it from [docker.com](https://www.docker.com/).
- Make sure Docker Desktop is running before starting ONLYOFFICE Desktop Editors.
- On Linux, verify that the Docker daemon is active: `sudo systemctl status docker`.
- On macOS and Windows, check that the Docker Desktop tray icon is present and shows a running state.

## The MCP server container fails to start

The server starts but immediately exits, or no tools appear in **AI Chat**. In **Settings** → **MCP Servers**, an error icon appears next to **onlyoffice-apps** in the **Permissions** section. Expand the server entry to see the connection log. Try any of these solutions to fix:

- Pull the latest image manually to make sure it is available locally:
  ```bash
  docker pull onlyoffice/docspace-mcp
  ```
- Run the container manually to see the full error output:
  ```bash
  docker run --interactive --rm \
    --env DOCSPACE_BASE_URL=https://your-instance.onlyoffice.com \
    --env DOCSPACE_API_KEY=your-api-key \
    onlyoffice/docspace-mcp
  ```
- Verify that the `DOCSPACE_BASE_URL` value is a valid, reachable URL (including `https://`).

## ONLYOFFICE Apps instance is not reachable

Connection timeout or `ERR_NAME_NOT_RESOLVED` when the server tries to reach `DOCSPACE_BASE_URL`. Confirm this error and fix it by:

- Confirm the URL is accessible from your machine by opening it in a browser.
- If you are using a VPN, make sure it is active and the ONLYOFFICE Apps domain resolves correctly.
- Check that your firewall does not block outgoing HTTPS connections from Docker containers.
- On Linux, you may need to configure Docker DNS settings in `/etc/docker/daemon.json`:
  ```json
  {
    "dns": [
      "8.8.8.8",
      "8.8.4.4"
    ]
  }
  ```


## Tool calls return 401 Unauthorized

The server starts without errors, but the tool call result in **AI Chat** contains `401 Unauthorized`. The server cannot authenticate with your ONLYOFFICE Apps instance. To fix:

- Check that `DOCSPACE_API_KEY` contains a valid API key, not the `your-api-key` placeholder.
- Make sure the API key is enabled and was not deleted in ONLYOFFICE Apps **Developer Tools** → **API keys**.
- Make sure `DOCSPACE_BASE_URL` points to the same instance where the API key was created.

After you fix the configuration, click **Save**. The server restarts with the new values.

## The AI model fails to call the tools

The tool call result contains an error like `filters: invalid_type Invalid input: expected object, received undefined`, and the model repeats the same call. Some models, especially smaller ones, do not pass the required tool parameters. Select a different model in **AI Chat** and try again.

## Invalid JSON in the configuration file

The configuration is not saved, or ONLYOFFICE Desktop Editors shows a parse error after clicking **Save**. Fix this by:

- Validate your JSON before saving. Common mistakes include trailing commas after the last property and unescaped special characters in values.
- Use an online JSON validator (e.g., [jsonlint.com](https://jsonlint.com)) to check the syntax.
- Make sure the `mcpServers` key is at the top level of the JSON object.

## Port conflict or container already running

An error stating that a container with the same name already exists. The configuration uses `--rm`, which removes the container automatically after it stops. If you see this error, a previous instance may still be running. To fix this:

1. Stop any existing containers:
  ```bash
  docker stop $(docker ps -q --filter ancestor=onlyoffice/docspace-mcp)
  ```
2. Restart the MCP server from ONLYOFFICE Desktop Editors.
