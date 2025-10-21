# ONLYOFFICE DocSpace MCP Server

[Model Context Protocol] (MCP) is a standardized protocol for managing context
between large language models (LLMs) and external systems. This repository
provides an MCP server for [ONLYOFFICE DocSpace].

The DocSpace MCP Server connects AI tools directly to ONLYOFFICE DocSpace. This gives AI agents, assistants, and chatbots the ability to manage rooms, collaborate on files, handle permissions, and automate document workflows - all through natural language interactions.

## Use Cases

- **Room Management**: Create, update, and archive rooms. Configure room types, manage membership, and control access levels.
- **Folder & File Operations**: Create folders, upload documents, copy or move items in batches, rename or delete content, and check file or folder details.
- **Collaboration & Permissions**: Invite or remove users, adjust security settings, and review current access rights for rooms and shared spaces.
- **Content Access**: Retrieve "My documents" or "Rooms" folders, get folder contents, download files as text, and monitor ongoing file operations.
- **Storage & Tariff Control**: Check current portal quota and subscription plan before uploading or sharing large volumes of data.
- **People Directory**: List all people in the portal to streamline invitations and access management.
- **Localization & Settings**: Access supported languages, cultures, and time zones to adapt collaboration spaces to regional preferences.

## Remote DocSpace MCP Server

The remote DocSpace MCP Server is hosted by ONLYOFFICE and provides the fastest way to start using DocSpace tools inside your AI agent. You can connect instantly without deploying or configuring anything on your machine.

If your MCP host does not support remote MCP servers, don’t worry - you can always run the local version of the [DocSpace MCP Server](docs/README.md) instead.

### Prerequisites

- *Node.js* v18+
- *npm* or *npx* installed
- A compatible MCP host with remote server support (Claude Desktop, etc.)
- An active DocSpace account with valid credentials
- Any applicable access policies enabled in your DocSpace portal

### Environment requirements

| Requirement          | Version               | Description                                       |
| -------------------- | --------------------- | ------------------------------------------------- |
| **Node.js**          | 18+                   | Required for running the server                   |
| **NPM**              | 9+                    | For package installation                          |
| **Operating System** | macOS, Windows, Linux | Cross-platform support                            |
| **Network Access**   | HTTPS                 | Required for connecting to your DocSpace instance |

## Connect to Claude Desktop

The DocSpace MCP Server can be used directly with Claude Desktop by adding it to your `claude_desktop_config.json` file. This allows Claude to interact with your DocSpace - creating rooms, managing files, and collaborating on content via natural language.

### Step 1. Locate your config file

Find your Claude Desktop configuration file, usually named:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

### Step 2. Add the DocSpace MCP Server entry

Insert the following block into the `mcpServers` section of your config:

``` json
{
  "mcpServers": {
    "onlyoffice-docspace": {
      "env": {
        "DOCSPACE_BASE_URL": "https://your-instance.onlyoffice.com",
        "DOCSPACE_API_KEY": "your-api-key"
      },
      "command": "npx",
      "args": ["--yes", "@onlyoffice/docspace-mcp"]
    }
  }
}
```

### Step 3. Set environment values

- `DOCSPACE_BASE_URL` → the URL of your DocSpace instance (e.g. https://portal.onlyoffice.com).
- `DOCSPACE_API_KEY` → your personal API key generated in DocSpace.

### Step 4. Restart Claude Desktop

Close and reopen Claude Desktop. The DocSpace MCP Server will start automatically, and you'll be able to issue natural language commands like:

- Create a new project room and invite Anna with editor rights.
- Upload this file to my Documents.

## Connect to Cursor

The DocSpace MCP Server can be used directly with Cursor by adding it to your `mcp.json` file. This allows Cursor to use DocSpace during the developing process: storing documentation, accessing project files.

### Step 1. Locate your config file

Find your Cursor configuration file, usually named:

- **Global (all projects)**: `~/.cursor/mcp.json`
- **Project-specific**: `.cursor/mcp.json` in project root

### Step 2. Add the DocSpace MCP Server entry

Insert the following block into the `mcpServers` section of your config:

``` json
{
  "mcpServers": {
    "onlyoffice-docspace": {
      "env": {
        "DOCSPACE_BASE_URL": "https://your-instance.onlyoffice.com",
        "DOCSPACE_API_KEY": "your-api-key"
      },
      "command": "npx",
      "args": ["--yes", "@onlyoffice/docspace-mcp"]
    }
  }
}
```

### Step 3. Set environment values

- `DOCSPACE_BASE_URL` → the URL of your DocSpace instance (e.g. https://portal.onlyoffice.com).
- `DOCSPACE_API_KEY` → your personal API key generated in DocSpace.

Тут стоит указать только обязательные значения, и можно добавить ссылку на docs с остальными значениями, что бы не путать пользователя.

### Step 4. Restart Cursor

Close and reopen Cursor. The DocSpace MCP Server will start automatically, and you'll be able to issue natural language commands like:

- Create the "Backend Project" room for the developers' team.
- Save the current README to the Docs folder.

## Connect to Windsurf

The DocSpace MCP Server can be used directly with Windsurf by adding it to your `mcp_config.json` file. Windsurf IDE with the integrated Cascade agent  allows editing code, managing files, and collaborating on content.

### Step 1. Locate your config file

Find your Windsurf configuration file, usually named `~/.codeium/windsurf/mcp_config.json` (global configuration only).

### Step 2. Add the DocSpace MCP Server entry

Insert the following block into the `mcpServers` section of your config:

``` json
{
  "mcpServers": {
    "onlyoffice-docspace": {
      "env": {
        "DOCSPACE_BASE_URL": "https://your-instance.onlyoffice.com",
        "DOCSPACE_API_KEY": "your-api-key"
      },
      "command": "npx",
      "args": ["--yes", "@onlyoffice/docspace-mcp"]
    }
  }
}
```

### Step 3. Set environment values

- `DOCSPACE_BASE_URL` → the URL of your DocSpace instance (e.g. https://portal.onlyoffice.com).
- `DOCSPACE_API_KEY` → your personal API key generated in DocSpace.

Тут стоит указать только обязательные значения, и можно добавить ссылку на docs с остальными значениями, что бы не путать пользователя.

### Step 4. Refresh

Click Refresh (🔄) in the MCP toolbar. The DocSpace MCP Server will start automatically, and you'll be able to issue natural language commands like:

- Archive the "Project Orion" room.
- Update the "summary.docx" file with a new version.

## Tools

The DocSpace MCP server supports the following MCP protocol features.

<details>
  <summary><code>files</code></summary>

| Name                    | Description              | Prompt                                                                       |
|-------------------------|--------------------------|------------------------------------------------------------------------------|
| `copy_batch_items`      | Copy to a folder.        | Copy the "sample1.docx" and "sample2.xlsx" files from "Drafts" to "Samples". |
| `delete_file`           | Delete a file.           | Delete the "operations.xlsx" file from the "Project" folder.                 |
| `download_file_as_text` | Download a file as text. | Download the "spec.docx" file and return its content as plain text.          |
| `get_file_info`         | Get file information.    | Return the information of the "project.docx" file.                           |
| `move_batch_items`      | Move to a folder.        | Move the "sample1.docx" and "sample2.xlsx" files from "Samples" to "Trash'.  |
| `update_file`           | Update a file.           | Update the "requirements.docx" file with a new version.                      |
| `upload_file`           | Upload a file.           | Upload the "report.pdf" file to the "Reports" folder.                        |

</details>

<details>
  <summary><code>folders</code></summary>

| Name                 | Description                    | Prompt                                                 |
|----------------------|--------------------------------|--------------------------------------------------------|
| `create_folder`      | Create a folder.               | Create the "Reports" folder in the "Project" room.     |
| `delete_folder`      | Delete a folder.               | Delete the "Samples" folder from the "Documents" room. |
| `get_folder_content` | Get content of a folder.       | Display the content of the "Contracts" folder.         |
| `get_folder_info`    | Get folder information.        | Return the information of the "Projects" folder.       |
| `get_my_folder`      | Get the "My Documents" folder. | Return the content of the "Me documents" folder.       |
| `rename_folder`      | Rename a folder.               | Rename the "Documents" folder to "New documents".      |

</details>

<details>
  <summary><code>people</code></summary>

| Name             | Description     | Prompt                                            |
|------------------|-----------------|---------------------------------------------------|
| `get_all_people` | Get all people. | Return all user profiles from the current portal. |

</details>

<details>
  <summary><code>rooms</code></summary>

| Name                     | Description                                             | Prompt                                                                       |
|--------------------------|---------------------------------------------------------|------------------------------------------------------------------------------|
| `archive_room`           | Archive a room.                                         | Archive the "Samples" room.                                                  |
| `create_room`            | Create a room.                                          | Create a new room named "Project" for the developers' team.                  |
| `get_room_access_levels` | Get a list of available room invitation access levels.  | Get the list of available invitation access levels for the "Documents" room. |
| `get_room_info`          | Get room information.                                   | Return the information of the "Project" room.                                |
| `get_room_security_info` | Get a list of users with their access levels to a room. | Get the list of users with their access levels to the "Documents" room.      |
| `get_room_types`         | Get a list of available room types.                     | Return the list of available room types.                                     |
| `get_rooms_folder`       | Get the "Rooms" folder.                                 | Return the content of the "Rooms" folder.                                    |
| `set_room_security`      | Invite or remove users from a room.                     | Invite John Smith to the "Project" room.                                     |
| `update_room`            | Update a room.                                          | Update the "Project" room.                                                   |

</details>

## Common prompts

Below are some examples of how to interact naturally with the MCP Server:

| Action          | Example Prompt                                          |
| --------------- | ------------------------------------------------------- |
| Create a folder | “Make a new folder called `Contracts` in my workspace.” |
| Upload a file   | “Upload `invoice.pdf` to `Documents`.”                  |
| Get room info   | “Show details of the `Marketing` room.”                 |
| Invite user     | “Add Alice to the `Design` room as viewer.”             |

## Testing

To verify installation and functionality:

``` sh
npm test
```

This runs all built-in integration tests. Tests cover basic CRUD operations for files, folders, and rooms.

## Security and threats

The DocSpace MCP Server follows the same authentication logic as DocSpace APIs.

### Potential Threats

- API key leakage — always store your API key in environment variables or vaults.
- Unauthorized access — limit key permissions using DocSpace’s access policy settings.
- Data exposure — avoid returning raw file data for sensitive documents.

### Recommendations

- Use HTTPS endpoints only
- Rotate API keys regularly
- Enable access logging in DocSpace

## Error Handling

Common errors and how to fix them:

| Error                       | Cause                    | Solution                                |
| --------------------------- | ------------------------ | --------------------------------------- |
| `401 Unauthorized`          | Invalid API key          | Check credentials and reissue a new key |
| `403 Forbidden`             | Insufficient permissions | Verify access policy settings           |
| `404 Not Found`             | Missing file or room     | Check object path or ID                 |
| `429 Too Many Requests`     | Rate limit reached       | Wait before retrying                    |
| `500 Internal Server Error` | DocSpace service issue   | Retry later or contact admin            |


## References

- [DocSpace MCP: Distribution]
- [DocSpace MCP: Installation on local server]
- [DocSpace MCP: Configuration]
- [DocSpace MCP: OAuth Authorization]
- [DocSpace MCP: Tools]

## License

The DocSpace MCP server is distributed under the Apache-2.0 license found in
the [LICENSE] file.

<!-- Footnotes -->

[docs]: https://github.com/ONLYOFFICE/docspace-mcp/tree/v2.0.0/docs
[LICENSE]: https://github.com/onlyoffice/docspace-mcp/blob/v2.0.0/LICENSE

[Model Context Protocol]: https://modelcontextprotocol.io/
[ONLYOFFICE DocSpace]: https://www.onlyoffice.com/docspace.aspx

[MCP: Tools]: https://modelcontextprotocol.io/specification/2025-06-18/server/tools/

[DocSpace MCP: Distribution]: ../distribution/README.md
[DocSpace MCP: OAuth Authorization]: ../authorization/oauth.md
[DocSpace MCP: Installation on local server]: ../installation/local-server.md
[DocSpace MCP: Configuration]: ../configuration/README.md
[DocSpace MCP: Tools]: ../features/tools.md
