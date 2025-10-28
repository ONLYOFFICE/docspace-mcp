# Docker MCP

This document describes how to install and run the DocSpace MCP server using
Docker's MCP Catalog and Toolkit.

## Contents

- [Docker MCP Server](#docker-mcp-server)
- [References](#references)

## Docker MCP Server

Using the Docker MCP Toolkit requires [Docker Desktop] to be installed on your
system and the [Docker MCP Toolkit] to be enabled. See the
[Enable Docker MCP Toolkit] guide for how to enable the Docker MCP Toolkit.

1. Install the DocSpace MCP server through the Docker Desktop interface using
  the [Install an MCP Server] guide, or by using the Docker CLI:

  ```sh
  docker mcp server enable onlyoffice-docspace
  ```

2. Connect the DocSpace MCP server to an MCP client through the Docker Desktop
  interface using the [Install an MCP Client] guide, or by using the Docker CLI:

  ```sh
  docker mcp client connect --global <client>
  ```

## References

- [Docker Docs: MCP Catalog and Toolkit]
- [Docker MCP: ONLYOFFICE DocSpace]

<!-- Footnotes -->

[Docker Desktop]: https://www.docker.com/products/docker-desktop/
[Docker MCP Toolkit]: https://docs.docker.com/ai/mcp-catalog-and-toolkit/toolkit/

[Enable Docker MCP Toolkit]: https://docs.docker.com/ai/mcp-catalog-and-toolkit/toolkit/#enable-docker-mcp-toolkit
[Install an MCP Server]: https://docs.docker.com/ai/mcp-catalog-and-toolkit/toolkit/#install-an-mcp-server
[Install an MCP Client]: https://docs.docker.com/ai/mcp-catalog-and-toolkit/toolkit/#install-an-mcp-client

[Docker Docs: MCP Catalog and Toolkit]: https://docs.docker.com/ai/mcp-catalog-and-toolkit/
[Docker MCP: ONLYOFFICE DocSpace]: https://hub.docker.com/mcp/server/onlyoffice-docspace/
