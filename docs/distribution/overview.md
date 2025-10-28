# Overview

This document provides an overview of available formats and their corresponding
distribution sources for the DocSpace MCP server.

## Contents

- [Available Formats](#available-formats)
	- [Docker Image](#docker-image)
	- [Docker MCP Server](#docker-mcp-server)
	- [MCP Bundle](#mcp-bundle)
	- [Node.js Application](#nodejs-application)
- [Distribution Matrix](#distribution-matrix)
- [References](#references)

## Available Formats

The DocSpace MCP server is distributed in four formats.

### Docker Image

A containerized version of the DocSpace MCP server.

### Docker MCP Server

An MCP server available through Docker's MCP Catalog and Toolkit.

### MCP Bundle

A bundled MCP server for applications that support the MCP Bundles format.

### Node.js Application

A standalone application that can be run on systems with Node.js.

## Distribution Matrix

The following table shows which formats are available from each distribution
source:

| Distribution Source | Docker Image | Docker MCP Server | MCP Bundle | Node.js Application |
| ------------------- | :----------: | :---------------: | :--------: | :-----------------: |
| [Build From Source] |      +       |         -         |     +      |          +          |
| [Docker Hub]        |      +       |         -         |     -      |          -          |
| [Docker MCP]        |      -       |         +         |     -      |          -          |
| [GitHub Releases]   |      -       |         -         |     +      |          +          |
| [npm Registry]      |      -       |         -         |     -      |          +          |

## References

- [Docker Docs: What is an image?]
- [Docker Docs: MCP Catalog and Toolkit]
- [GitHub Anthropic: MCP Bundles]

<!-- Footnotes -->

[Docker Docs: What is an image?]: https://docs.docker.com/get-started/docker-concepts/the-basics/what-is-an-image/
[Docker Docs: MCP Catalog and Toolkit]: https://docs.docker.com/ai/mcp-catalog-and-toolkit/
[GitHub Anthropic: MCP Bundles]: https://github.com/anthropics/mcpb/

[Build From Source]: ./build-from-source.md
[Docker Hub]: ./docker-hub.md
[Docker MCP]: ./docker-mcp.md
[GitHub Releases]: ./github-releases.md
[npm Registry]: ./npm-registry.md
