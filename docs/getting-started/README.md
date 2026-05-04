# About the DocSpace MCP server

[Model Context Protocol](https://modelcontextprotocol.io/docs/getting-started/intro) is a standardized protocol for managing context between large language models (LLMs) and external systems. 
The DocSpace MCP Server connects AI tools directly to ONLYOFFICE DocSpace. This gives AI agents, assistants, and chatbots the ability to manage rooms, collaborate on files, handle permissions, and automate document workflows — all through natural language interactions.

- [Quickstart](quickstart.md) — Get started with the DocSpace MCP server
- [Connect to MCP clients](clients.md) — Connect MCP server to clients and start communicating with your DocSpace

## Features

- **Control what AI can access** - The DocSpace MCP server offers access to [tools with fine-grained enable/disable capabilities](../reference/tools.md) that enable only the DocSpace operations you need, from full workspace management to read-only file access, ensuring security and privacy when needed.
- **Flexible integration** - Offers different methods to [integrate with any MCP-compatible AI client](clients.md) without changing your infrastructure.
- **Secure by default** - Choose your preferred [authentication method](auth.md), from OAuth for enterprise security to API keys for quick testing.
- **Customize per conversation** - Different AI assistants can have different permissions and access levels in the same DocSpace instance.
- **Deploy anywhere** - The numerous [distribution formats](../distribution/README.md) available allow you to run in Docker, your existing Node.js environment, or as a standalone service - whatever fits your stack best.

## Use Cases

- **Project Management**: [Set up rooms](../tutorials/setup-project-room.md) and manage membership to these rooms based on access levels. Track who can access what files, and [archive rooms once they are completed](../tutorials/project-archival.md).
- **[Bulk document operations](../tutorials/doc-lifecycle-management.md)**: Create folders, upload documents, copy or move items in batches, rename or delete content, and check file or folder details.
- **Compliance and audits**: [Control document access with precision](../tutorials/onboarding.md#step-4-define-who-has-access), especially for legal and finance teams with strict data regulations, by controlling access to confidential files and conducting audits to determine who accessed certain files and when.
- **[Remote team collaboration](../tutorials/onboarding.md)**: Work with distributed teams by inviting or removing users, adjusting security settings, and reviewing current access rights for rooms and shared spaces.
- **Content discovery**: Retrieve "My documents" or "Rooms" folders, get folder contents, download files as text, and monitor ongoing file operations.
- **People Directory**: List all people in the portal to streamline invitations and access management.
