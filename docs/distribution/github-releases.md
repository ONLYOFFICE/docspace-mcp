# GitHub Releases

This document describes how to download and use the DocSpace MCP server from
GitHub releases.

## Contents

- [MCP Bundle](#mcp-bundle)
- [Node.js Application](#nodejs-application)

## MCP Bundle

Running the MCP bundle requires [Node.js] version 18 or higher to be installed
on your system.

1. Download the latest release from GitHub:

  ```sh
  VERSION=3.1.0 curl --location --output docspace-mcp.mcpb https://github.com/ONLYOFFICE/docspace-mcp/releases/v$VERSION/download/onlyoffice-docspace-mcp-$VERSION.mcpb
  ```

  To download a specific version:

  ```sh
  VERSION=<version> curl --location --output docspace-mcp.mcpb https://github.com/ONLYOFFICE/docspace-mcp/releases/v$VERSION/download/onlyoffice-docspace-mcp-$VERSION.mcpb
  ```

2. Use the downloaded `.mcpb` file in an application that supports MCP bundles.

## Node.js Application

Running the Node.js application requires [Node.js] version 18 or higher to be
installed on your system.

1. Download the latest release from GitHub:

  ```sh
  VERSION=3.1.0 curl --location --output docspace-mcp.tgz https://github.com/ONLYOFFICE/docspace-mcp/releases/v$VERSION/download/onlyoffice-docspace-mcp-$VERSION.tgz
  ```

  To download a specific version:

  ```sh
  VERSION=<version> curl --location --output docspace-mcp.tgz https://github.com/ONLYOFFICE/docspace-mcp/releases/v$VERSION/download/onlyoffice-docspace-mcp-$VERSION.tgz
  ```

2. Extract the downloaded archive:

  ```sh
  tar --extract --gzip --file docspace-mcp.tgz
  ```

3. Navigate to the extracted directory:

  ```sh
  cd docspace-mcp
  ```

4. Run the Node.js application:

  ```sh
  ./bin/onlyoffice-docspace-mcp
  ```

## References

- [GitHub Docs: About Releases]
- [GitHub Anthropic: MCP Bundles]
- [GitHub ONLYOFFICE: DocSpace MCP Server Releases]

<!-- Footnotes -->

[Node.js]: https://nodejs.org/

[GitHub Docs: About Releases]: https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases
[GitHub Anthropic: MCP Bundles]: https://github.com/anthropics/mcpb/
[GitHub ONLYOFFICE: DocSpace MCP Server Releases]: https://github.com/ONLYOFFICE/docspace-mcp/releases/
