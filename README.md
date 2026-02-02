# ONLYOFFICE DocSpace MCP Server

[Model Context Protocol] (MCP) is a standardized protocol for managing context
between large language models (LLMs) and external systems. This repository
provides an MCP server for [ONLYOFFICE DocSpace].

The DocSpace MCP Server connects AI tools directly to ONLYOFFICE DocSpace. This gives AI agents, assistants, and chatbots the ability to manage rooms, collaborate on files, handle permissions, and automate document workflows - all through natural language interactions.

## Features

- **Tools with granular control** - Access to [tools](/docs/tools.md) organized into logical
  toolsets with fine-grained enable/disable capabilities and meta tools.
- **Multiple transport protocols** - Support for stdio, SSE, and Streamable HTTP
  [transports](/docs/configuration/global-configuration.md#user-content-docspace_transport).
- **Different authentication methods** - Supports API keys, Personal Access
  Tokens, Basic authentication, and OAuth 2.0 with dynamic client registration. See [examples](/docs/installation.md#user-content-examples).
- **Request-level configuration** - Configure authentication and tool selection
  during session initialization using [custom HTTP headers](/docs/configuration/request-configuration.md#user-content-header-options).
- **Various distribution formats** - Available in multiple formats like [Docker image](/docs/distribution/docker-hub.md#user-content-docker-image), [Docker MCP
  Server](/docs/distribution/docker-mcp.md#user-content-docker-mcp-server), [MCP bundle](/docs/distribution/build-from-source.md#user-content-mcp-bundle), and [Node.js application](/docs/distribution/npm-registry.md#user-content-nodejs-application).

## Use Cases

- **Room Management**: Create, update, and archive rooms. Configure room types, manage membership, and control access levels.
- **Folder & File Operations**: Create folders, upload documents, copy or move items in batches, rename or delete content, and check file or folder details.
- **Collaboration & Permissions**: Invite or remove users, adjust security settings, and review current access rights for rooms and shared spaces.
- **Content Access**: Retrieve "My documents" or "Rooms" folders, get folder contents, download files as text, and monitor ongoing file operations.
- **People Directory**: List all people in the portal to streamline invitations and access management.

## Connecting Clients to DocSpace MCP Server

You can connect to the DocSpace MCP server using any MCP clients. We have covered some popular clients, such as Claude Desktop, Cursor, Windsurf, etc., and [here](docs/clients/README.md) you can read about it.

### Remote DocSpace MCP Server

The remote DocSpace MCP Server is hosted by ONLYOFFICE and provides the fastest way to start using DocSpace tools inside your AI agent. You can connect to it instantly without deploying or configuring anything on your machine.

The public instance is available at https://mcp.onlyoffice.com/mcp for clients
that support modern Streamable HTTP transport and at
https://mcp.onlyoffice.com/sse for clients that support only the legacy SSE
transport. It is preferable to use the Streamable HTTP transport whenever possible.

See all options for connecting clients to the Remote DocSpace MCP Server [here](/docs/installation/remote-server.md).

### Local DocSpace MCP Server

If your MCP host does not support remote MCP servers, you can run the [local version](/docs/installation/local-server.md) of the DocSpace MCP Server instead.

Most clients that implement the MCP protocol have a common configuration file in the `JSON` format, inside which you can add the ONLYOFFICE DocSpace MCP Local Server.


## License

The DocSpace MCP server is distributed under the Apache-2.0 license found in
the [LICENSE] file.

<!-- Footnotes -->

[docs]: https://github.com/ONLYOFFICE/docspace-mcp/tree/main/docs
[LICENSE]: https://github.com/ONLYOFFICE/docspace-mcp/blob/main/LICENSE

[Model Context Protocol]: https://modelcontextprotocol.io/
[ONLYOFFICE DocSpace]: https://www.onlyoffice.com/docspace.aspx

[MCP specification]: https://modelcontextprotocol.io/specification/2025-11-25/server/tools/