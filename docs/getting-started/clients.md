# Connect DocSpace MCP server to MCP clients

The DocSpace MCP server allows you to connect numerous MCP clients, offering flexibility to choose between interfaces when interacting with your DocSpace. This guide demonstrates how to connect the DocSpace MCP server to the following clients:

- [ONLYOFFICE Desktop Editors](#connect-to-onlyoffice-desktop-editors)
- [Claude Desktop](#connect-to-claude-desktop)
- [Claude Web](#connect-to-claude-web)
- [Cursor](#connect-to-cursor)
- [Le Chat](#connect-to-le-chat)
- [VS Code](#connect-to-vs-code)
- [Windsurf](#connect-to-windsurf)

## Before you start

Take note of these environment variables used when configuring the DocSpace MCP server:

- `DOCSPACE_BASE_URL` — the URL of your DocSpace instance (e.g., `https://portal.onlyoffice.com`).
- `DOCSPACE_API_KEY` — your personal API key generated in DocSpace settings → **Developer Tools** → **API Keys**.

**Ensure your API key is valid**.

For local (command-based) connections, [Docker](https://www.docker.com/) must also be installed on your system.

## Connect to ONLYOFFICE Desktop Editors

Connect to the locally running MCP server using stdio transport.

1. Open ONLYOFFICE Desktop Editors.
2. Navigate to **AI agent**.
3. Navigate to **Settings**.
4. Navigate to **MCP Servers**.
5. Click **Edit configuration**.
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

7. Click **Save**.

## Connect to Claude Desktop

Claude Desktop offers three different ways to connect to the DocSpace MCP server:

- [Connectors](#connect-via-connectors)
- [Extensions](#connect-via-extensions)
- [Local MCP servers](#connect-via-local-mcp)

### Connect via connectors

Connect to the MCP server running remotely using Claude's Connectors. This is the preferred connection method.

1. Open Claude Desktop.
2. Navigate to Settings.
3. Navigate to Connectors.
4. Click "Add custom connector".
5. Enter a name for the connector (e.g., "ONLYOFFICE DocSpace MCP").
6. Enter the connection URL (e.g., https://mcp.onlyoffice.com/mcp).
7. Follow based on your authentication preference:
    - **OAuth with public app**: Click **Add**
    - **OAuth with custom app**:
        1. Click "Advanced settings".
        2. In the "OAuth Client ID" field, enter the Client ID from your [DocSpace OAuth application](https://api.onlyoffice.com/docspace/api-backend/get-started/authentication/oauth2/creating-oauth-app/).
        3. In the "OAuth Client Secret" field, enter the Client Secret from your DocSpace OAuth application.
        4. Click "Add".
8. Click "Connect" next to the newly added connector.
9. Complete the OAuth authentication process:
    - Sign in to your DocSpace account by entering your email and password and clicking "Sign In".
    - If you have more than one account associated with the entered email, choose one of them.
    - Allow the MCP Remote Server to access the specified data in your DocSpace account.

### Connect via extensions

Connect to the locally running MCP server using Claude's Extensions. Before connecting, ensure you have:

- Node.js (v18 or higher)
- Download the GitHub MCP bundle. Follow [these steps](../distribution/distribution-combined.md#download-the-github-release) to install Node and the GitHub release.

1. Open Claude Desktop.
2. Navigate to Settings.
3. Navigate to Extensions.
4. Click "Advanced settings".
5. Click "Install extension".
6. Select the downloaded MCP bundle.
7. Click "Install".

### Connect via local MCP

Connect to the locally running MCP server using Claude's Local MCP servers.

1. Open Claude Desktop.
2. Navigate to Settings.
3. Navigate to Developer.
4. Click "Edit config".
5. Open the configuration file in a text editor.
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
7. Save the file.

## Connect to Claude Web

1. Open Claude Web in your web browser.
2. Navigate to Settings.
3. Navigate to Connectors.
4. Click "Add custom connector".
5. Enter a name for the connector (e.g., "ONLYOFFICE DocSpace MCP").
6. Enter connection URL based on your preferred authentication method:
    - **OAuth with public app (Recommended)**
        - Enter the connection URL (e.g., https://mcp.onlyoffice.com/mcp).
    - **Authentication with URL-encoded credentials**:
        - Enter the connection URL with your encoded credentials:
       `https://{encoded_username}:{encoded_password}@mcp.onlyoffice.com/mcp?base_url=https://your-instance.onlyoffice.com/`
        - Replace `{encoded_username}` with your URL-encoded DocSpace email
        - Replace `{encoded_password}` with your URL-encoded DocSpace password
        - Replace `your-instance.onlyoffice.com` with your actual DocSpace domain
7. Click "Add".
8. Click "Connect" next to the newly added connector.
9. If you chose OAuth, complete the authentication process:
    - Sign in to your DocSpace account by entering your email and password and clicking "Sign In".
    - If you have more than one account associated with the entered email, choose one of them.
    - Allow the MCP Remote Server to access the specified data in your DocSpace account.

## Connect to Cursor

Cursor allows you to connect to the DocSpace MCP server either via:

- (Recommended) [HTTP](#connect-cursor-to-remote-docspace-mcp-server-via-http) 
- [Command](#connect-cursor-to-local-docspace-mcp-server-via-command)

### Connect Cursor to remote DocSpace MCP server via HTTP

Connect to the MCP server running remotely using Streamable-HTTP transport.

1. Open Cursor.
2. Bring up Command Palette.
3. Select **View: Open MCP Settings**.
4. Click **Add Custom MCP**.
5. Add a new record to the `mcpServers` section:
   ```json
   {
   	"mcpServers": {
   		"onlyoffice-docspace": {
   			"type": "http",
   			"url": "https://mcp.onlyoffice.com/mcp"
   		}
   	}
   }
   ```
6. Save the file.
7. Navigate back to **MCP Settings**.
8. Click **Connect** next to the newly added MCP server.
9. Complete the OAuth authentication process:
    - Sign in to your DocSpace account by entering your email and password and clicking **Sign In**.
    - If you have more than one account associated with the entered email, choose one of them.
    - Allow the MCP Remote Server to access the specified data in your DocSpace account.
    
### Connect Cursor to local DocSpace MCP server via command

Connect to the locally running MCP server using stdio transport.

1. Open Cursor.
2. Bring up Command Palette.
3. Select **View: Open MCP Settings**.
4. Click **Add Custom MCP**.
5. Add a new record to the `mcpServers` section:
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
6. Enter the values of the `DOCSPACE_BASE_URL` and `DOCSPACE_API_KEY` environment variables. 
7. Save the file.

## Connect to Le Chat

1. Open Le Chat in your web browser.
2. Navigate to Intelligence.
3. Navigate to Connectors.
4. Click **Add Connector**.
5. Navigate to Custom MCP Connector.
6. Enter a name for the connector (e.g., "ONLYOFFICE_DocSpace_MCP").
7. Enter the server URL based on your preferred authentication method:
    - **OAuth**: `https://mcp.onlyoffice.com/mcp` 
    - **API Token Authentication**: server URL with your DocSpace instance as a query parameter:
   `https://mcp.onlyoffice.com/mcp?base_url=https://your-instance.onlyoffice.com`
   (replace the base_url value with your actual DocSpace URL).
8. Authenticate the connection with any of these auth methods:
    - **OAuth**: 
        - Select **OAuth 2.1** from **Authentication method**. 
        - Enter your **Client ID** and **Client Secret** gotten from [creating your custom app on DocSpace](https://api.onlyoffice.com/docspace/api-backend/get-started/authentication/oauth2/creating-oauth-app/)
    - **API Token**: 
        - Select "API Token Authentication" from "Authentication Methods" section and 
        - In the "Header value" field, enter your personal API key generated in DocSpace settings -> Developer Tools -> API keys.
9. Click **Connect**.
10. Confirm connection by enabling the DocSpace MCP server in the **Enable tools** section of the chat bar.

## Connect to VS Code

VS Code client also connects to DocSpace MCP server using:

- [HTTP](#connect-vs-code-to-remote-docspace-mcp-server-via-http)
- [Command](#connect-vs-code-to-local-docspace-mcp-server-via-command)

### Connect VS Code to remote DocSpace MCP server via HTTP

This is the preferred connection method and connects to the remote MCP server using Streamable-HTTP transport. 

1. Open Visual Studio Code.
2. Bring up Command Palette.
3. Select **MCP: Open User Configuration**.
4. Add a new record to the `servers` section:
   ```json
   {
   	"servers": {
   		"onlyoffice-docspace": {
   			"type": "http",
   			"url": "https://mcp.onlyoffice.com/mcp"
   		}
   	}
   }
   ```
5. Save the file.
6. Bring up Command Palette.
7. Select **MCP: List Servers**.
8. Select **onlyoffice-docspace**.
9. Select **Start Server**.
10. Complete the OAuth authentication process:
    - Sign in to your DocSpace account by entering your email and password and clicking **Sign In**.
    - If you have more than one account associated with the entered email, choose one of them.
    - Allow the MCP Remote Server to access the specified data in your DocSpace account.

### Connect VS Code to local DocSpace MCP server via command

Connect to the locally running MCP server using stdio transport.

1. Open Visual Studio Code.
2. Bring up Command Palette.
3. Select **MCP: Open User Configuration**.
4. Add a new record to the `servers` section:
   ```json
   {
   	"servers": {
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
5. Save the file.
6. Bring up Command Palette.
7. Select **MCP: List Servers**.
8. Select **onlyoffice-docspace**.
9. Select **Start Server**.

## Connect to Windsurf

Windsurf offers two ways to connect to the DocSpace MCP server:

- [HTTP](#connect-windsurf-to-remote-docspace-mcp-server-via-http)
- [Command](#connect-windsurf-to-local-docspace-mcp-server-via-command)

### Connect Windsurf to remote DocSpace MCP server via HTTP

This is the recommended method and connects to the remote MCP server using Streamable-HTTP transport.

1. Open Windsurf.
2. Bring up Command Palette.
3. Select **Open Windsurf User Settings**.
4. Navigate to **Cascade**.
5. Click **Open MCP Marketplace**.
6. Click **Settings**.
7. Add a new record to the `mcpServers` section:
   ```json
   {
   	"mcpServers": {
   		"onlyoffice-docspace": {
   			"serverUrl": "https://mcp.onlyoffice.com/mcp"
   		}
   	}
   }
   ```
8. Save the file.
9. Complete the OAuth authentication process:
    - Sign in to your DocSpace account by entering your email and password and clicking **Sign In**.
    - If you have more than one account associated with the entered email, choose one of them.
    - Allow the MCP Remote Server to access the specified data in your DocSpace account.

### Connect Windsurf to local DocSpace MCP server via command

This method uses stdio transport to connect to a locally running MCP server.

1. Open Windsurf.
2. Bring up Command Palette.
3. Select **Open Windsurf User Settings**.
4. Navigate to **Cascade**.
5. Click **Open MCP Marketplace**.
6. Click **Settings**.
7. Add a new record to the `mcpServers` section:
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
8. Save the file.
9. Open **Cascade**. 
10. Click **Actions(...)**. You'll find **onlyoffice-docspace** under the MCP section if connection was successful. Toggle to enable the connection.
