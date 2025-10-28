# Troubleshooting

This document describes common configuration issues when working with the
DocSpace MCP server.

## Contents

- [Parsing Errors](#parsing-errors)
- [References](#references)

## Parsing Errors

If an error occurs during global configuration parsing, the DocSpace MCP server
will automatically fall back to using the stdio transport and defer the
configuration error until tool execution:

0. Encounter an error while parsing global configuration.
1. Start successfully using stdio transport.
2. Respond normally to MCP protocol requests.
3. Return the original configuration parsing error when any tool is called.

This fallback behavior is implemented to ensure compatibility with the Docker
MCP Registry, which requires servers to start successfully even with
configuration issues.

## References

- [Docker Docs: MCP Catalog and Toolkit]
- [DocSpace MCP: Global Configuration]

<!-- Footnotes -->

[Docker Docs: MCP Catalog and Toolkit]: https://docs.docker.com/ai/mcp-catalog-and-toolkit/

[DocSpace MCP: Global Configuration]: ./global-configuration.md
