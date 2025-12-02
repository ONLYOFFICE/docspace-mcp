# OAuth

This document describes how to create OAuth applications for the DocSpace MCP
server and the limitations it addresses through a proxy architecture.

## Contents

- [Creating an Application](#creating-an-application)
- [Limitations](#limitations)
  - [Dynamic Client Registration](#dynamic-client-registration)
  - [Scope Handling](#scope-handling)
- [References](#references)

## Creating an Application

To create an OAuth application for use with the MCP server, follow the [DocSpace
OAuth application creation guide][DocSpace API: Creating OAuth Application].
When configuring the application, ensure the following settings are properly
configured:

- **Redirect URIs**: Set to the MCP server's callback endpoint. For the public
  instance, use https://mcp.onlyoffice.com/oauth/callback. For self-hosted
  instances, replace the base URL with your MCP server's URL;
- **Allowed Origins**: Set to the MCP server's base URL. For the public
  instance, use https://mcp.onlyoffice.com. For self-hosted instances, use your
  MCP server's URL;
- **PKCE**: Enable PKCE (Proof Key for Code Exchange) for the application.

After creating the application, note the **Client ID** and **Client Secret**
values. Use these credentials to configure the MCP server or provide them
through the MCP client interface.

## Limitations

The DocSpace authorization server has limitations that prevent MCP clients from
using the OAuth flow. The MCP server acts as an OAuth proxy to address these
limitations.

### Dynamic Client Registration

The DocSpace authorization server does not support OAuth dynamic client
registration, which the MCP authorization specification relies on. Without this
support, MCP clients cannot register themselves directly with the DocSpace
authorization server.

The MCP server addresses this limitation by operating in one of two modes:

1. When configured with pre-defined OAuth credentials, the MCP server exposes a
   registration endpoint that returns these credentials to all MCP clients. All
   MCP clients effectively share the same OAuth application;
2. When configured without pre-defined OAuth credentials, the MCP server expects
   users to provide their own OAuth client credentials through the MCP client
   interface.

The first mode is optional. The second mode is always available when the OAuth
is enabled.

### Scope Handling

The MCP server modifies the OAuth flow to address scope-related compatibility
issues between MCP clients and the DocSpace authorization server:

1. Some MCP clients request scopes that the DocSpace authorization server does
   not recognize, causing the authorization server to reject the request. The
   MCP server ignores all scope parameters from incoming requests and omits them
   when forwarding to the authorization server. The DocSpace authorization
   server interprets requests without scope parameters as requesting all scopes
   granted to the application;
2. Some MCP clients validate scope values in token responses. When the DocSpace
   authorization server returns all scopes granted to the application, these
   clients may fail or display errors if the returned scopes differ from those
   they requested. The MCP server removes scope values from token responses
   before returning them to MCP clients.

Users effectively operate with all permissions granted to the OAuth application,
regardless of which scopes the MCP client originally requested.

## References

- [RFC 6749: The OAuth 2.0 Authorization Framework]
- [RFC 7591: OAuth 2.0 Dynamic Client Registration Protocol]
- [MCP: Authorization]
- [DocSpace API: OAuth]
- [DocSpace MCP: Authentication Resolution]
- [DocSpace MCP: Global Configuration]
- [DocSpace MCP: Remote Server]

<!-- Definitions -->

[RFC 6749: The OAuth 2.0 Authorization Framework]: https://www.rfc-editor.org/rfc/rfc6749
[RFC 7591: OAuth 2.0 Dynamic Client Registration Protocol]: https://www.rfc-editor.org/rfc/rfc7591

[MCP: Authorization]: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization

[DocSpace API: OAuth]: https://api.onlyoffice.com/docspace/api-backend/get-started/authentication/oauth2/
[DocSpace API: Creating OAuth Application]: https://api.onlyoffice.com/docspace/api-backend/get-started/authentication/oauth2/creating-oauth-app/

[DocSpace MCP: Authentication Resolution]: ../configuration/authentication-resolution.md
[DocSpace MCP: Global Configuration]: ../configuration/global-configuration.md
[DocSpace MCP: Remote Server]: ../installation/remote-server.md
