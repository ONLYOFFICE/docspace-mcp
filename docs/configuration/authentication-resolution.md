# Authentication Resolution

This document describes how the DocSpace MCP server resolves authentication
methods based on transport configuration and available authentication options.

## Contents

- [Visualization](#visualization)
  - [Global Configuration](#global-configuration)
    - [stdio Transport](#stdio-transport)
    - [HTTP-like Transport](#http-like-transport)
  - [Request Configuration](#request-configuration)
- [References](#references)

## Visualization

The authentication resolution process depends on the transport type used and the
authentication methods configured. The following flowcharts illustrate how
authentication is resolved for different scenarios.

### Global Configuration

During application startup, the DocSpace MCP server validates the configured
authentication methods based on the selected transport protocol.

#### stdio Transport

For stdio transport, exactly one authentication method must be configured.

```mermaid
flowchart TD
	S[Start application] --> A[Load global configuration]
	A --> C{Check authentication methods}
	C -->|None configured| E[Error: At least one authentication method required]
	C -->|Exactly one configured| F[Start server with authentication]
	C -->|Multiple configured| D[Error: Only one authentication method allowed]
```

#### HTTP-like Transport

HTTP-like transports support optional authentication, allowing servers to run
with or without authentication depending on the use case.

```mermaid
flowchart TD
	S[Start application] --> A[Load global configuration]
	A --> G{Check authentication methods}
	G -->|None configured| J[Start server without authentication]
	G -->|Exactly one configured| I{OAuth enabled?}
	G -->|Multiple configured| H[Error: Only one authentication method allowed]
	I -->|No| Q[Start server with non-OAuth authentication]
	I -->|Yes| P[Start server with OAuth]
```

### Request Configuration

For HTTP-like transports, authentication can be configured on the request level
using query parameters and custom headers, unless OAuth is being used.

```mermaid
flowchart TD
	K[On initialization request] --> A[Load request configuration]
	A --> L{OAuth enabled?}
	L -->|No| O{Check authentication methods}
	L -->|Yes| M[Skip: OAuth handles authentication]
	O -->|None configured| P[Error: At least one authentication method required]
	O -->|Exactly one configured| Q[Create authenticated session]
	O -->|Multiple configured| R[Error: Only one authentication method allowed]
```

## References

- [DocSpace MCP: Global Configuration]
- [DocSpace MCP: Request Configuration]

<!-- Definitions -->

[DocSpace MCP: Global Configuration]: ./global-configuration.md
[DocSpace MCP: Request Configuration]: ./request-configuration.md
