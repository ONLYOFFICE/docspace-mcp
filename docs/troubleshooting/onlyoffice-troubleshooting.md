# Resolving errors with the ONLYOFFICE Desktop Editors

The following issues can occur when connecting the ONLYOFFICE Desktop Editors to the DocSpace MCP server.

## Docker is not found or not running

The MCP server fails to start with an error like `command not found: docker` or `Cannot connect to the Docker daemon`. To fix:

- Make sure Docker Desktop is installed. Download it from [docker.com](https://www.docker.com/).
- Make sure Docker Desktop is running before starting ONLYOFFICE Desktop Editors.
- On Linux, verify that the Docker daemon is active: `sudo systemctl status docker`.
- On macOS and Windows, check that the Docker Desktop tray icon is present and shows a running state.

## The MCP server container fails to start

The server starts but immediately exits, or no tools appear in the AI agent. Try any of these solutions to fix:

- Pull the latest image manually to make sure it is available locally:
  ```bash
  docker pull onlyoffice/docspace-mcp
  ```
- Check Docker logs for detailed error output:
  ```bash
  docker logs $(docker ps -lq)
  ```
- Verify that the `DOCSPACE_BASE_URL` value is a valid, reachable URL (including `https://`).

## DocSpace instance is not reachable

Connection timeout or `ERR_NAME_NOT_RESOLVED` when the server tries to reach `DOCSPACE_BASE_URL`. Confirm this error and fix it by:

- Confirm the URL is accessible from your machine by opening it in a browser.
- If you are using a VPN, make sure it is active and the DocSpace domain resolves correctly.
- Check that your firewall does not block outgoing HTTPS connections from Docker containers.
- On Linux, you may need to configure Docker DNS settings in `/etc/docker/daemon.json`:
  ```json
  {
    "dns": ["8.8.8.8", "8.8.4.4"]
  }
  ```

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
