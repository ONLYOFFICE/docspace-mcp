# Local Server

This document describes how to set up and configure the DocSpace MCP server to
run on your machine.

## Contents

- [Quick Install](#quick-install)
- [Docker Image](#docker-image)
- [Docker MCP Server](#docker-mcp-server)
- [MCP Bundle](#mcp-bundle)
- [Node.js Application](#nodejs-application)
- [References](#references)

## Quick Install

<!--generate quick-install-start-->

| Docker Image | Node.js Application |
|:-:|:-:|
| [![Add to Cursor using Docker Image](https://badgen.net/static/Add%20to/Cursor/black)](https://cursor.com/en/install-mcp?name=onlyoffice-docspace&config=eyJjb21tYW5kIjoiZG9ja2VyIiwiYXJncyI6WyJydW4iLCItLWludGVyYWN0aXZlIiwiLS1ybSIsIi0tZW52IiwiRE9DU1BBQ0VfQkFTRV9VUkwiLCItLWVudiIsIkRPQ1NQQUNFX0FQSV9LRVkiLCJvbmx5b2ZmaWNlL2RvY3NwYWNlLW1jcCJdLCJlbnYiOnsiRE9DU1BBQ0VfQkFTRV9VUkwiOiJodHRwczovL3lvdXItaW5zdGFuY2Uub25seW9mZmljZS5jb20iLCJET0NTUEFDRV9BUElfS0VZIjoieW91ci1hcGkta2V5In19) | [![Add to Cursor using npx](https://badgen.net/static/Add%20to/Cursor/black)](https://cursor.com/en/install-mcp?name=onlyoffice-docspace&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyItLXllcyIsIkBvbmx5b2ZmaWNlL2RvY3NwYWNlLW1jcCJdLCJlbnYiOnsiRE9DU1BBQ0VfQkFTRV9VUkwiOiJodHRwczovL3lvdXItaW5zdGFuY2Uub25seW9mZmljZS5jb20iLCJET0NTUEFDRV9BUElfS0VZIjoieW91ci1hcGkta2V5In19) |
| [![Add to VS Code using Docker Image](https://badgen.net/static/Add%20to/VS%20Code/blue)](https://insiders.vscode.dev/redirect/mcp/install?name=onlyoffice-docspace&inputs=%5B%7B%22type%22%3A%22promptString%22%2C%22id%22%3A%22docspace_base_url%22%2C%22description%22%3A%22The+base+URL+of+the+DocSpace+instance+for+API+requests.%22%7D%2C%7B%22type%22%3A%22promptString%22%2C%22id%22%3A%22docspace_api_key%22%2C%22description%22%3A%22The+API+key+for+accessing+the+DocSpace+API.%22%2C%22password%22%3Atrue%7D%5D&config=%7B%22command%22%3A%22docker%22%2C%22args%22%3A%5B%22run%22%2C%22--interactive%22%2C%22--rm%22%2C%22--env%22%2C%22DOCSPACE_BASE_URL%22%2C%22--env%22%2C%22DOCSPACE_API_KEY%22%2C%22onlyoffice%2Fdocspace-mcp%22%5D%2C%22env%22%3A%7B%22DOCSPACE_BASE_URL%22%3A%22%24%7Binput%3Adocspace_base_url%7D%22%2C%22DOCSPACE_API_KEY%22%3A%22%24%7Binput%3Adocspace_api_key%7D%22%7D%7D) | [![Add to VS Code using npx](https://badgen.net/static/Add%20to/VS%20Code/blue)](https://insiders.vscode.dev/redirect/mcp/install?name=onlyoffice-docspace&inputs=%5B%7B%22type%22%3A%22promptString%22%2C%22id%22%3A%22docspace_base_url%22%2C%22description%22%3A%22The+base+URL+of+the+DocSpace+instance+for+API+requests.%22%7D%2C%7B%22type%22%3A%22promptString%22%2C%22id%22%3A%22docspace_api_key%22%2C%22description%22%3A%22The+API+key+for+accessing+the+DocSpace+API.%22%2C%22password%22%3Atrue%7D%5D&config=%7B%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22--yes%22%2C%22%40onlyoffice%2Fdocspace-mcp%22%5D%2C%22env%22%3A%7B%22DOCSPACE_BASE_URL%22%3A%22https%3A%2F%2Fyour-instance.onlyoffice.com%22%2C%22DOCSPACE_API_KEY%22%3A%22your-api-key%22%7D%7D) |
| [![Add to VS Code Insiders using Docker Image](https://badgen.net/static/Add%20to/VS%20Code%20Insiders/cyan)](https://insiders.vscode.dev/redirect/mcp/install?name=onlyoffice-docspace&inputs=%5B%7B%22type%22%3A%22promptString%22%2C%22id%22%3A%22docspace_base_url%22%2C%22description%22%3A%22The+base+URL+of+the+DocSpace+instance+for+API+requests.%22%7D%2C%7B%22type%22%3A%22promptString%22%2C%22id%22%3A%22docspace_api_key%22%2C%22description%22%3A%22The+API+key+for+accessing+the+DocSpace+API.%22%2C%22password%22%3Atrue%7D%5D&config=%7B%22command%22%3A%22docker%22%2C%22args%22%3A%5B%22run%22%2C%22--interactive%22%2C%22--rm%22%2C%22--env%22%2C%22DOCSPACE_BASE_URL%22%2C%22--env%22%2C%22DOCSPACE_API_KEY%22%2C%22onlyoffice%2Fdocspace-mcp%22%5D%2C%22env%22%3A%7B%22DOCSPACE_BASE_URL%22%3A%22%24%7Binput%3Adocspace_base_url%7D%22%2C%22DOCSPACE_API_KEY%22%3A%22%24%7Binput%3Adocspace_api_key%7D%22%7D%7D&quality=insiders) | [![Add to VS Code Insiders using npx](https://badgen.net/static/Add%20to/VS%20Code%20Insiders/cyan)](https://insiders.vscode.dev/redirect/mcp/install?name=onlyoffice-docspace&inputs=%5B%7B%22type%22%3A%22promptString%22%2C%22id%22%3A%22docspace_base_url%22%2C%22description%22%3A%22The+base+URL+of+the+DocSpace+instance+for+API+requests.%22%7D%2C%7B%22type%22%3A%22promptString%22%2C%22id%22%3A%22docspace_api_key%22%2C%22description%22%3A%22The+API+key+for+accessing+the+DocSpace+API.%22%2C%22password%22%3Atrue%7D%5D&config=%7B%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22--yes%22%2C%22%40onlyoffice%2Fdocspace-mcp%22%5D%2C%22env%22%3A%7B%22DOCSPACE_BASE_URL%22%3A%22https%3A%2F%2Fyour-instance.onlyoffice.com%22%2C%22DOCSPACE_API_KEY%22%3A%22your-api-key%22%7D%7D&quality=insiders) |

<!--generate quick-install-end-->

## Docker Image

Using the Docker image requires [Docker] to be installed on your system.

Configure your MCP client to use the Docker image by adding the following
configuration to your client's configuration file:

```json
{
	"mcpServers": {
		"onlyoffice-docspace": {
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

## Docker MCP Server

Using the Docker MCP Toolkit requires [Docker Desktop] to be installed on your
system and the [Docker MCP Toolkit] to be enabled. See the
[Enable Docker MCP Toolkit] guide for how to enable the Docker MCP Toolkit.

1. Install the server through the Docker Desktop interface using the
  [Install an MCP Server] guide.

2. Connect the server to a MCP client through the Docker Desktop interface using
  the [Install an MCP Client] guide.

3. Configure the server through the Docker Desktop interface.

## MCP Bundle

Running the MCP bundle requires [Node.js] version 18 or higher to be installed
on your system.

1. Download the latest MCP bundle from [GitHub Releases].

2. Install the MCP bundle in an application by following the application's MCP
  bundles installation procedure.

3. Configure the server through the application's interface.

## Node.js Application

Running the Node.js application requires [Node.js] version 18 or higher to be
installed on your system.

Configure your MCP client to use the Node.js application by adding the following
configuration to your client's configuration file:

```json
{
	"mcpServers": {
		"onlyoffice-docspace": {
			"command": "npx",
			"args": ["--yes", "@onlyoffice/docspace-mcp"],
			"env": {
				"DOCSPACE_BASE_URL": "https://your-instance.onlyoffice.com",
				"DOCSPACE_API_KEY": "your-api-key"
			}
		}
	}
}
```

## References

- [Docker Docs: What is an image?]
- [Docker Docs: MCP Catalog and Toolkit]
- [GitHub Anthropic: MCP Bundles]
- [MCP: Connect to Local MCP Servers]
- [MCP: Example Clients]
- [Docker MCP: Distribution]
- [Docker MCP: Configuration]

<!-- Footnotes -->

[Docker]: https://www.docker.com/
[Docker Desktop]: https://www.docker.com/products/docker-desktop/
[Docker MCP Toolkit]: https://docs.docker.com/ai/mcp-catalog-and-toolkit/toolkit/
[GitHub Releases]: https://github.com/ONLYOFFICE/docspace-mcp/releases/
[Node.js]: https://nodejs.org/

[Enable Docker MCP Toolkit]: https://docs.docker.com/ai/mcp-catalog-and-toolkit/toolkit/#enable-docker-mcp-toolkit
[Install an MCP Server]: https://docs.docker.com/ai/mcp-catalog-and-toolkit/toolkit/#install-an-mcp-server
[Install an MCP Client]: https://docs.docker.com/ai/mcp-catalog-and-toolkit/toolkit/#install-an-mcp-client

[Docker Docs: What is an image?]: https://docs.docker.com/get-started/docker-concepts/the-basics/what-is-an-image/
[Docker Docs: MCP Catalog and Toolkit]: https://docs.docker.com/ai/mcp-catalog-and-toolkit/
[GitHub Anthropic: MCP Bundles]: https://github.com/anthropics/mcpb/

[MCP: Connect to Local MCP Servers]: https://modelcontextprotocol.io/quickstart/user
[MCP: Example Clients]: https://modelcontextprotocol.io/clients

[Docker MCP: Distribution]: ../distribution/README.md
[Docker MCP: Configuration]: ../configuration/README.md
