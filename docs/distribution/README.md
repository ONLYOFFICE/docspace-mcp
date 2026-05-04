# Distribution overview

The DocSpace MCP server is available in several formats from different distribution sources.

## Available Formats

The DocSpace MCP server is distributed in four formats.

- **Docker Image**: A containerized version of the DocSpace MCP server.
- **Docker MCP Server**: An MCP server available through Docker's MCP Catalog and Toolkit.
- **MCP Bundle**: A bundled MCP server for applications that support the MCP Bundles format.
- **Node.js Application**: A standalone application that can be run on systems with Node.js.

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

[Build From Source]: ./distribution-combined.md#build-the-mcp-server-from-source
[Docker Hub]: ./distribution-combined.md#pull-from-docker-hub
[Docker MCP]: ./distribution-combined.md#build-with-docker-mcp-toolkit
[GitHub Releases]: ./distribution-combined.md#download-the-github-release
[npm Registry]: ./distribution-combined.md#build-with-npm-registry
