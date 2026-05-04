# Getting started with the DocSpace MCP server

Connect the [DocSpace MCP server](README.md) to Claude Desktop and start interacting with your DocSpace through natural language.

## Step 1: Connect to MCP client

[MCP clients](clients.md) like Claude, VS Code, and Windsurf act as a bridge to the DocSpace MCP server, enabling LLMs to access and use DocSpace workspace and tools, thus improving the overall capabilities of DocSpace. This guide uses the Claude Desktop client and connects to a local MCP server. You can also [access via a remote server](installation.md#access-via-the-remote-docspace-mcp-server).

> **Note:** Ensure Docker is installed on your system.

To connect Claude Desktop to your local MCP server:

1. Open Claude Desktop.
2. Navigate to **Settings**.
3. Navigate to **Developer**.
4. Click **Edit config**.
5. Open the configuration file (`config.json`) in a text editor.
6. Add a new record to the `mcpServers` section:
   ```json
   {
    "mcpServers": {
        "onlyoffice-docspace": {
            "command": "docker",
            "args": [
                "run",
                "--interactive",
                "--rm",
                "--env",
                "DOCSPACE_BASE_URL",
                "--env",
                "DOCSPACE_API_KEY",
                "onlyoffice/docspace-mcp"
            ],
            "env": {
                "DOCSPACE_BASE_URL": "https://your-instance.onlyoffice.com",
                "DOCSPACE_API_KEY": "your-api-key"
            }
        }
    }
   }
   ```

Where:
- `DOCSPACE_BASE_URL` - the URL of your DocSpace instance (e.g. https://portal.onlyoffice.com).
- `DOCSPACE_API_KEY` - your personal API key generated in DocSpace **Settings** -> **Developer Tools** -> **API keys**.

7. Save the file and quit Claude Desktop.

> **Note:** It's important to quit and not just close the Claude Desktop window as quitting and restarting the app reloads the `config.json` configuration with the new `mcpServers` entry.

## Step 2: Confirm the connection

1. Open Claude Desktop.
2. Click **+** > **Connectors** on the chat bar.

   Our newly configured MCP server (**onlyoffice-docspace**) is now enabled.

![This image confirms a successful client-DocSpace MCP server connection](/docs/img/confirm-connection.light.png#gh-light-mode-only)![This image confirms a successful client-DocSpace MCP server connection](/docs/img/confirm-connection.dark.png#gh-dark-mode-only)

## Step 3: Interact with your DocSpace using the newly connected client

Now we have our connection, let us interact with DocSpace via Claude:

1. Let's create a new room. Claude requests permission to create this room.

![This image shows the command to create a room](/docs/img/create-new-room.light.png#gh-light-mode-only)![This image shows the command to create a room](/docs/img/create-new-room.dark.png#gh-dark-mode-only)

   You can confirm this new room in your DocSpace account.

![This image confirms the room was successfully created](/docs/img/confirm-room-on-docspace.light.png#gh-light-mode-only)![This image confirms the room was successfully created](/docs/img/confirm-room-on-docspace.dark.png#gh-dark-mode-only)

2. Now, create a new document in this room.

![This image shows the command for creating a new document](/docs/img/create-new-doc.light.png#gh-light-mode-only)![This image shows the command for creating a new document](/docs/img/create-new-doc.dark.png#gh-dark-mode-only)

   Confirm the new document was created.

![This image confirms the document was created](/docs/img/confirm-new-doc.light.png#gh-light-mode-only)![This image confirms the document was created](/docs/img/confirm-new-doc.dark.png#gh-dark-mode-only)

   You can confirm the existence of this new document in the new room in your DocSpace.

![This image shows the new document visible inside the new room in DocSpace](/docs/img/confirm-new-doc-in-new-room.light.png#gh-light-mode-only)![This image shows the new document visible inside the new room in DocSpace](/docs/img/confirm-new-doc-in-new-room.dark.png#gh-dark-mode-only)

## Next steps

- [Discover other ways to connect to DocSpace MCP server](installation.md)
- Learn how to explore this connection for tasks like [onboarding team members](../tutorials/onboarding.md), [managing projects](../tutorials/setup-project-room.md), and effectively [archiving projects after completion](../tutorials/project-archival.md).
