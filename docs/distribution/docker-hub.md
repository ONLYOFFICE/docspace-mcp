# Docker Hub

This document describes how to install and run the DocSpace MCP server using the
Docker image from Docker Hub.

## Contents

- [Docker Image](#docker-image)
- [References](#references)

## Docker Image

Using the Docker image requires [Docker] to be installed on your system.

1. Pull the latest DocSpace MCP server image from Docker Hub:

  ```sh
  docker pull onlyoffice/docspace-mcp
  ```

  To pull a specific version:

  ```sh
  docker pull onlyoffice/docspace-mcp:<version>
  ```

2. Run the Docker container:

  ```sh
  docker run --interactive --rm onlyoffice/docspace-mcp
  ```

## References

- [Docker Docs: What is an image?]
- [Docker Hub: ONLYOFFICE DocSpace MCP Server]

<!-- Footnotes  -->

[Docker]: https://www.docker.com/

[Docker Docs: What is an image?]: https://docs.docker.com/get-started/docker-concepts/the-basics/what-is-an-image/
[Docker Hub: ONLYOFFICE DocSpace MCP Server]: https://hub.docker.com/r/onlyoffice/docspace-mcp
