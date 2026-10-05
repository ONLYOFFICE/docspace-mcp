# Installing the ONLYOFFICE Apps MCP server

Before interacting with the ONLYOFFICE Apps MCP server, you need to install or connect to it. ONLYOFFICE Apps offers two ways to do this:

- [Access via a local machine](#access-via-a-local-onlyoffice-apps-mcp-server)
- [Access via a remote server](#access-via-the-remote-onlyoffice-apps-mcp-server)

## Before you start

- Ensure you have an ONLYOFFICE Apps Instance. [Sign up to ONLYOFFICE Apps](https://www.onlyoffice.com/docspace-registration?utm_source=api&utm_medium=article&utm_campaign=mcpserver) to access your instance and get an API key.
- Choose your desired client. You can build a custom client or [choose from the different MCP clients](clients.md) available based on your integration, features, user interface, or security needs.

## Access via a local ONLYOFFICE Apps MCP server

You can configure your local machine to interact with the ONLYOFFICE Apps MCP server using:

- [Quick install](#quick-install)
- [Docker image](#install-with-docker-image)
- [Docker MCP Toolkit](#install-with-docker-mcp-toolkit)
- [MCP bundle](#install-with-mcp-bundle)
- [Node.js application](#install-via-nodejs-application)

Before proceeding, ensure to set these environment variables:

- `DOCSPACE_BASE_URL` - the URL of your ONLYOFFICE Apps instance (e.g. https://your-instance.onlyoffice.com).
- `DOCSPACE_API_KEY` - your personal API key generated in ONLYOFFICE Apps **Developer Tools** → **API keys** (open **Developer Tools** from the banner at the bottom of the left sidebar).

### Quick install

Use the buttons below to add the ONLYOFFICE Apps MCP server to your client in one click. VS Code prompts for the environment variable values during installation; in Cursor, replace the placeholder values in the generated configuration.

<!--generate quick-install-start-->

| Docker Image | Node.js Application |
|:-:|:-:|
| [![Add to Cursor using Docker Image](https://badgen.net/static/Add%20to/Cursor/black)](https://cursor.com/en/install-mcp?name=onlyoffice-apps&config=eyJjb21tYW5kIjoiZG9ja2VyIiwiYXJncyI6WyJydW4iLCItLWludGVyYWN0aXZlIiwiLS1ybSIsIi0tZW52IiwiRE9DU1BBQ0VfQkFTRV9VUkwiLCItLWVudiIsIkRPQ1NQQUNFX0FQSV9LRVkiLCJvbmx5b2ZmaWNlL2RvY3NwYWNlLW1jcCJdLCJlbnYiOnsiRE9DU1BBQ0VfQkFTRV9VUkwiOiJodHRwczovL3lvdXItaW5zdGFuY2Uub25seW9mZmljZS5jb20iLCJET0NTUEFDRV9BUElfS0VZIjoieW91ci1hcGkta2V5In19) | [![Add to Cursor using npx](https://badgen.net/static/Add%20to/Cursor/black)](https://cursor.com/en/install-mcp?name=onlyoffice-apps&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyItLXllcyIsIkBvbmx5b2ZmaWNlL2RvY3NwYWNlLW1jcCJdLCJlbnYiOnsiRE9DU1BBQ0VfQkFTRV9VUkwiOiJodHRwczovL3lvdXItaW5zdGFuY2Uub25seW9mZmljZS5jb20iLCJET0NTUEFDRV9BUElfS0VZIjoieW91ci1hcGkta2V5In19) |
| [![Add to VS Code using Docker Image](https://badgen.net/static/Add%20to/VS%20Code/blue)](https://insiders.vscode.dev/redirect/mcp/install?name=onlyoffice-apps&inputs=%5B%7B%22type%22%3A%22promptString%22%2C%22id%22%3A%22docspace_base_url%22%2C%22description%22%3A%22The+base+URL+of+the+ONLYOFFICE+Apps+instance+for+API+requests.%22%7D%2C%7B%22type%22%3A%22promptString%22%2C%22id%22%3A%22docspace_api_key%22%2C%22description%22%3A%22The+API+key+for+accessing+the+ONLYOFFICE+Apps+API.%22%2C%22password%22%3Atrue%7D%5D&config=%7B%22command%22%3A%22docker%22%2C%22args%22%3A%5B%22run%22%2C%22--interactive%22%2C%22--rm%22%2C%22--env%22%2C%22DOCSPACE_BASE_URL%22%2C%22--env%22%2C%22DOCSPACE_API_KEY%22%2C%22onlyoffice%2Fdocspace-mcp%22%5D%2C%22env%22%3A%7B%22DOCSPACE_BASE_URL%22%3A%22%24%7Binput%3Adocspace_base_url%7D%22%2C%22DOCSPACE_API_KEY%22%3A%22%24%7Binput%3Adocspace_api_key%7D%22%7D%7D) | [![Add to VS Code using npx](https://badgen.net/static/Add%20to/VS%20Code/blue)](https://insiders.vscode.dev/redirect/mcp/install?name=onlyoffice-apps&inputs=%5B%7B%22type%22%3A%22promptString%22%2C%22id%22%3A%22docspace_base_url%22%2C%22description%22%3A%22The+base+URL+of+the+ONLYOFFICE+Apps+instance+for+API+requests.%22%7D%2C%7B%22type%22%3A%22promptString%22%2C%22id%22%3A%22docspace_api_key%22%2C%22description%22%3A%22The+API+key+for+accessing+the+ONLYOFFICE+Apps+API.%22%2C%22password%22%3Atrue%7D%5D&config=%7B%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22--yes%22%2C%22%40onlyoffice%2Fdocspace-mcp%22%5D%2C%22env%22%3A%7B%22DOCSPACE_BASE_URL%22%3A%22https%3A%2F%2Fyour-instance.onlyoffice.com%22%2C%22DOCSPACE_API_KEY%22%3A%22your-api-key%22%7D%7D) |
| [![Add to VS Code Insiders using Docker Image](https://badgen.net/static/Add%20to/VS%20Code%20Insiders/cyan)](https://insiders.vscode.dev/redirect/mcp/install?name=onlyoffice-apps&inputs=%5B%7B%22type%22%3A%22promptString%22%2C%22id%22%3A%22docspace_base_url%22%2C%22description%22%3A%22The+base+URL+of+the+ONLYOFFICE+Apps+instance+for+API+requests.%22%7D%2C%7B%22type%22%3A%22promptString%22%2C%22id%22%3A%22docspace_api_key%22%2C%22description%22%3A%22The+API+key+for+accessing+the+ONLYOFFICE+Apps+API.%22%2C%22password%22%3Atrue%7D%5D&config=%7B%22command%22%3A%22docker%22%2C%22args%22%3A%5B%22run%22%2C%22--interactive%22%2C%22--rm%22%2C%22--env%22%2C%22DOCSPACE_BASE_URL%22%2C%22--env%22%2C%22DOCSPACE_API_KEY%22%2C%22onlyoffice%2Fdocspace-mcp%22%5D%2C%22env%22%3A%7B%22DOCSPACE_BASE_URL%22%3A%22%24%7Binput%3Adocspace_base_url%7D%22%2C%22DOCSPACE_API_KEY%22%3A%22%24%7Binput%3Adocspace_api_key%7D%22%7D%7D&quality=insiders) | [![Add to VS Code Insiders using npx](https://badgen.net/static/Add%20to/VS%20Code%20Insiders/cyan)](https://insiders.vscode.dev/redirect/mcp/install?name=onlyoffice-apps&inputs=%5B%7B%22type%22%3A%22promptString%22%2C%22id%22%3A%22docspace_base_url%22%2C%22description%22%3A%22The+base+URL+of+the+ONLYOFFICE+Apps+instance+for+API+requests.%22%7D%2C%7B%22type%22%3A%22promptString%22%2C%22id%22%3A%22docspace_api_key%22%2C%22description%22%3A%22The+API+key+for+accessing+the+ONLYOFFICE+Apps+API.%22%2C%22password%22%3Atrue%7D%5D&config=%7B%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22--yes%22%2C%22%40onlyoffice%2Fdocspace-mcp%22%5D%2C%22env%22%3A%7B%22DOCSPACE_BASE_URL%22%3A%22https%3A%2F%2Fyour-instance.onlyoffice.com%22%2C%22DOCSPACE_API_KEY%22%3A%22your-api-key%22%7D%7D&quality=insiders) |

<!--generate quick-install-end-->

### Install with Docker image

1. [Follow these steps](../distribution/distribution-combined.md#pull-from-docker-hub) to pull the latest ONLYOFFICE Apps MCP server from Docker Hub
2. Locate your MCP client `.json` config file. The location of this file depends on the specific client.

3. Add the ONLYOFFICE Apps MCP Server entry

Insert the following block into the `mcpServers` section of your `.json` configuration file:

```json
{
  "mcpServers": {
    "onlyoffice-apps": {
      "command": "docker",
      "args": [
        "run",
        "--interactive",
        "--rm",
        "--env",
        "DOCSPACE_BASE_URL",
        "--env",
        "DOCSPACE_API_KEY",
        "onlyoffice/docspace-mcp"
      ],
      "env": {
        "DOCSPACE_BASE_URL": "https://your-instance.onlyoffice.com",
        "DOCSPACE_API_KEY": "your-api-key"
      }
    }
  }
}
```

**Configuration options**

| Option | Description |
|--------|-------------|
| `docker` | The executable to run |
| `run` | Command to create and start a container |
| `--rm` | Automatically remove the container when it exits |
| `--env` | Flag to pass environment variables |
| `onlyoffice/docspace-mcp` | Docker image name to run |


### Install with Docker MCP Toolkit

Using the [Docker MCP Toolkit](https://docs.docker.com/ai/mcp-catalog-and-toolkit/toolkit/) requires [Docker Desktop](https://docs.docker.com/desktop/) to be installed on your
system and the Docker MCP Toolkit to be enabled. 

> **Note:** The Docker MCP Toolkit is currently a beta feature and is only available to specific user segments, subscription tiers, or by invitation.

1. Follow [this guide](../distribution/distribution-combined.md#build-with-docker-mcp-toolkit) to install the server through the Docker Desktop interface.

2. [Connect the server to an MCP client](https://docs.docker.com/ai/mcp-catalog-and-toolkit/get-started/#add-mcp-servers) through the Docker Desktop interface.

3. Configure the server through the Docker Desktop interface. In general:

    - Select the ONLYOFFICE Apps MCP server in Docker Desktop
    - Open the server's configuration or settings panel
    - Enter your ONLYOFFICE Apps base URL (e.g., `https://your-instance.onlyoffice.com`)
    - Enter your personal API key
    - Save the configuration

### Install with MCP bundle

Running the MCP bundle requires [Node.js](https://nodejs.org/en/download) version 18 or higher to be installed on your system.

1. Download the latest MCP bundle from [GitHub Releases](../distribution/distribution-combined.md#download-the-mcp-bundle-github-release) (typically named `docspace-mcp-bundle-x.x.x.zip` or similar).

2. Install the MCP bundle in an application by following the application's MCP bundles installation procedure.

3. Configure the server through the application's interface. In general:

    - Open the server settings within your application
    - Enter your ONLYOFFICE Apps base URL (e.g., `https://your-instance.onlyoffice.com`)
    - Enter your personal API key 
    - Save the configuration and restart the application if required

### Install via Node.js application

> **Note:** Running the Node.js application requires Node.js version 18 or higher to be installed on your system.

Configure your MCP client to use the Node.js application by adding the following
configuration to your client's configuration file:

```json
{
  "mcpServers": {
    "onlyoffice-apps": {
      "command": "npx",
      "args": [
        "--yes",
        "@onlyoffice/docspace-mcp"
      ],
      "env": {
        "DOCSPACE_BASE_URL": "https://your-instance.onlyoffice.com",
        "DOCSPACE_API_KEY": "your-api-key"
      }
    }
  }
}
```

**Configuration options**

| Option | Description |
|--------|-------------|
| `npx` | The Node.js package runner, which downloads and executes packages on demand |
| `--yes` | Automatically confirms the installation prompt, enabling unattended startup |
| `@onlyoffice/docspace-mcp` | The official ONLYOFFICE Apps MCP server package from npm |

## Access via the remote ONLYOFFICE Apps MCP server

Another way to use the ONLYOFFICE Apps MCP server is to access it via a public ONLYOFFICE Apps MCP Server instance hosted by ONLYOFFICE. This eliminates the need to run your own server infrastructure while providing access to ONLYOFFICE Apps functionality through your AI assistant. To do this, provide the ONLYOFFICE Apps MCP server public instance URL when [connecting to any of the MCP clients](clients.md). 

## Public instance

The public instance is available at two endpoints:

| **Endpoint**                   | **Transport**             | **Recommendation**                                                                                                         |
|--------------------------------|---------------------------|----------------------------------------------------------------------------------------------------------------------------|
| https://mcp.onlyoffice.com/mcp | HTTP                      | Preferred - Use this endpoint whenever your client supports it. Streamable HTTP offers better performance and reliability. |
| https://mcp.onlyoffice.com/sse | Server-Sent Events (SSE) | Legacy - Use this endpoint only if your client does not support the modern Streamable HTTP transport.                      |

The public instance provides access to all available tools by default. Tool selection can be customized using query parameters or custom headers. However, we recommend using the MCP client interface for tool configuration when supported.

## Tool configuration

Tool selection can be customized using the following options:

- **MCP Client Interface**: (Preferred) Most MCP clients provide a built-in interface for [enabling or disabling specific tools](../reference/tools-resolution.md#enable-a-tool-from-unspecified-toolset). Use this method when your client supports it.

- **Query Parameters or Custom Headers**: For clients without a tool configuration interface, you can [customize tool availability by passing parameters in the connection URL or via custom HTTP headers](../reference/request-configuration.md#enabled_tools).

## Authenticating the remote MCP server-client connection

The public instance supports multiple authentication methods to meet different security requirements and client capabilities: OAuth, API key, Personal Access Token (PAT), username/password pair, or raw `Authorization` header.

> **Note:** OAuth is the recommended method as it provides the strongest security model by allowing users to authorize specific permissions without sharing their credentials directly.

| **Authentication method**      | **Definition**                                                                  | **Requirements**                         | **Recommendations**                                                                                                                   |
|--------------------------------|---------------------------------------------------------------------------------|------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------|
| OAuth (public app)             | Authenticates the connection without requiring custom credentials               | Connection URL                           | Simplest and most secure method, requiring no custom credentials or additional configuration                                          |
| OAuth (custom app)             | Connects using a client ID and client secret after [creating a custom app](https://api.onlyoffice.com/docspace/api-backend/get-started/authentication/oauth2/creating-oauth-app/)    | Connection URL, Client ID, Client Secret | Offers more flexibility and full control over the OAuth configuration, including custom redirect URIs, specific scopes, and branding. |
| API Key (Header)               | Connect using an API key and base URL configured via custom headers             | Connection URL, API key                  | Ideal when integrating with platforms that support custom HTTP headers but don't have built-in OAuth support                          |
| API Key (Authorization header) | Connect using API key in `Authorization` header and base URL in query parameter | Connection URL, API key                  | Ideal when working with clients that support Bearer token authentication but don't allow custom headers                                          |
| Username & password in URL     | Connect using URL-encoded credentials and base URL in query parameter           | Connection URL, username, password       | Ideal for quick setup, testing, or when using clients with limited authentication options                                             |

## After installation

- [Test MCP server-client installation](quickstart.md#step-2-confirm-the-connection)
- [Start exploring with the MCP server by creating a new room](quickstart.md#step-3-interact-with-your-onlyoffice-apps-using-the-newly-connected-client)
