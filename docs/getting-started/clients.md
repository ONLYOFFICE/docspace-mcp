# Connect ONLYOFFICE Apps MCP server to MCP clients

The ONLYOFFICE Apps MCP server allows you to connect numerous MCP clients, offering flexibility to choose between interfaces when interacting with your ONLYOFFICE Apps. This guide demonstrates how to connect the ONLYOFFICE Apps MCP server to the following clients:

- [ONLYOFFICE Apps](#connect-to-onlyoffice-apps)
- [ONLYOFFICE Desktop Editors](#connect-to-onlyoffice-desktop-editors)
- [Claude Desktop](#connect-to-claude-desktop)
- [Claude Web](#connect-to-claude-web)
- [Cursor](#connect-to-cursor)
- [Mistral Vibe](#connect-to-mistral-vibe)
- [VS Code](#connect-to-vs-code)
- [Devin Desktop](#connect-to-devin-desktop)

## Before you start

Take note of these environment variables used when configuring the ONLYOFFICE Apps MCP server:

- `DOCSPACE_BASE_URL` — the URL of your ONLYOFFICE Apps instance (e.g., `https://your-instance.onlyoffice.com`).
- `DOCSPACE_API_KEY` — your personal API key generated in ONLYOFFICE Apps **Developer Tools** → **API keys** (open **Developer Tools** from the banner at the bottom of the left sidebar).

**Ensure your API key is valid**.

For local (command-based) connections, [Docker](https://www.docker.com/) must also be installed on your system.

## Connect to ONLYOFFICE Apps

Connect the ONLYOFFICE Apps MCP server to AI Chat in your ONLYOFFICE Apps workspace. The server connects via HTTP and authenticates with an API key.

Only the workspace owner and Full admins can configure MCP servers.

> **Note:** To use the MCP server tools in AI Chat, activate the AI features add-on in your workspace: click **Activate** in the banner at the top of the **AI settings** page or enable the add-on in **Billing** → **Add-ons**. AI usage is billed from your Wallet.

1. In ONLYOFFICE Apps, navigate to **Settings** → **AI settings** and open the **MCP servers** tab.
2. Click **Edit configuration**.
3. Add the `onlyoffice-apps` record to the `mcpServers` section and replace the `X-Mcp-Base-Url` and `X-Mcp-Api-Key` values with your workspace URL and your personal API key generated in ONLYOFFICE Apps **Developer Tools** → **API keys**:

```json
{
  "mcpServers": {
    "onlyoffice-apps": {
      "type": "http",
      "url": "https://mcp.onlyoffice.com/mcp",
      "headers": {
        "X-Mcp-Base-Url": "https://your-instance.onlyoffice.com",
        "X-Mcp-Api-Key": "your-api-key"
      }
    }
  }
}
```

4. Click **Save**. The server appears in the **Permissions** section.
5. Make sure the **onlyoffice-apps** toggle is on. To enable or disable individual tools, use the toggles next to them.

Once enabled, the server tools are available to workspace users in AI Chat, both in rooms and folders and in AI agents. In an AI agent, only the users with the **Agent manager** or **Content creator** role can use the chat.

> **Note:** In AI Chat, the server tools work with the access rights of the current user. Users can access only the rooms and files available to them.

If the server fails to connect, an error icon appears next to it in the **Permissions** section. Expand the server entry to see the connection log. The `HTTP 401 Unauthorized` error means that the `headers` block is missing or the API key is invalid.

## Connect to ONLYOFFICE Desktop Editors

Connect to the locally running MCP server using stdio transport.

> **Note:** These steps apply to ONLYOFFICE Desktop Editors 10.0 and later.

1. Open ONLYOFFICE Desktop Editors.
2. In the left panel, click **AI Tools**. If AI Tools are not installed yet, click **Accept & Install**, and then restart the application.
3. Connect an AI model. In the **AI Chat** panel, select a provider, enter its API key, select a model, and click **Add Model**. You can also do this later in **Settings** → **AI Models**. The **MCP Servers** settings are unavailable until at least one AI model is added.
4. In the left panel, click **Settings** and navigate to **MCP Servers**.
5. Click **Edit configuration**.
6. Add the `onlyoffice-apps` record to the `mcpServers` section and replace the `DOCSPACE_BASE_URL` and `DOCSPACE_API_KEY` values with your own:

```json
{
  "mcpServers": {
    "onlyoffice-apps": {
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

7. Click **Save**. The server starts automatically and appears in the **Permissions** section.
8. Make sure the **onlyoffice-apps** toggle is on. To enable or disable individual tools, expand the server entry.

You can now use the ONLYOFFICE Apps tools in **AI Chat**.

## Connect to Claude Desktop

Claude Desktop offers three different ways to connect to the ONLYOFFICE Apps MCP server:

- [Connectors](#connect-via-connectors)
- [Extensions](#connect-via-extensions)
- [Local MCP servers](#connect-via-local-mcp)

### Connect via connectors

Connect to the MCP server running remotely using Claude's Connectors. This is the preferred connection method.

1. Open Claude Desktop.
2. Navigate to **Settings** → **Connectors**.
3. Click **Add** → **Add custom connector**.
4. Enter a name for the connector (e.g., "ONLYOFFICE Apps MCP") and the connection URL `https://mcp.onlyoffice.com/mcp`, and then click **Continue**.
5. Select the authentication settings based on your preference, and then click **Add**:
    - **OAuth with public app**: Keep the detected settings: **Sign in now** and **Register automatically**.
    - **OAuth with custom app**: Keep **Sign in now**, select **Use your own OAuth client**, and enter the Client ID and Client Secret from your [ONLYOFFICE Apps OAuth application](https://api.onlyoffice.com/docspace/api-backend/get-started/authentication/oauth2/creating-oauth-app/). When creating the application:
        - Add `https://mcp.onlyoffice.com/oauth/callback` to **Redirects URLs**.
        - Add `https://mcp.onlyoffice.com` to **Allowed origins**.
        - Select the **Write** access for **Profile**, **Contacts**, **Rooms**, and **Files & Folders**, and select **Open ID**.
6. Click **Connect**. Claude Desktop opens your browser.
7. On the **Finish connecting a connector?** page, click **Continue connecting**.
8. Complete the OAuth authentication process:
    - Sign in to your ONLYOFFICE Apps account by entering your email and password and clicking **Sign In**.
    - If you have more than one account associated with the entered email, choose one of them.
    - Allow the application to access the specified data in your ONLYOFFICE Apps account.
9. When the browser asks to open Claude, click **Open Claude**.

   The connector page shows the **Disconnect** button and the list of tool permissions.

> **Note:** Connectors are linked to your Claude account. A connector added in Claude Desktop is also available in Claude Web, and vice versa. On the Claude Free plan, you can add only one custom connector.

### Connect via extensions

Connect to the locally running MCP server using Claude's Extensions. Before connecting, download the MCP bundle file (`onlyoffice-docspace-mcp-<version>.mcpb`) from the **Assets** section of the [latest GitHub release](https://github.com/ONLYOFFICE/docspace-mcp/releases/latest). For other download options, see [Download the MCP bundle GitHub release](../distribution/distribution-combined.md#download-the-mcp-bundle-github-release).

> **Note:** Claude Desktop includes a built-in Node.js runtime for extensions, so you do not need to install Node.js separately.

1. Open Claude Desktop.
2. Navigate to **Settings** → **Extensions**.
3. Click **Advanced settings** → **Install extension**, and select the downloaded MCP bundle file. Alternatively, drag the file to the **Extensions** page.
4. In the extension window, click **Install**, and then confirm the installation.
5. On the extension page, click **Configure**.
6. Fill in the extension settings, and then click **Save**:
    - **Base URL**: the URL of your ONLYOFFICE Apps instance (e.g., `https://your-instance.onlyoffice.com`).
    - **API Key**: your personal API key generated in ONLYOFFICE Apps **Developer Tools** → **API keys**.

   The extension is enabled, and its tools are available in Claude.

### Connect via local MCP

Connect to the locally running MCP server using Claude's Local MCP servers.

1. Open Claude Desktop.
2. Navigate to Settings.
3. Navigate to Developer.
4. Click "Edit config".
5. Open the configuration file (`claude_desktop_config.json`) in a text editor.
6. Add the `mcpServers` section from the example below to the top level of the file. If the file already contains other settings, copy the example without its outer braces and separate it from the existing settings with a comma:
   ```json
   {
     "mcpServers": {
       "onlyoffice-apps": {
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
7. Save the file, then fully quit Claude Desktop and relaunch it. Closing the window is not enough, as Claude Desktop reads the configuration only at startup.

## Connect to Claude Web

1. Open [Claude Web](https://claude.ai) in your web browser.
2. Navigate to **Settings** → **Connectors**.
3. Click **Add** → **Add custom connector**.
4. Enter a name for the connector (e.g., "ONLYOFFICE Apps MCP").
5. Enter the connection URL based on your preferred authentication method, and then click **Continue**:
    - **OAuth with public app (Recommended)**: `https://mcp.onlyoffice.com/mcp`
    - **Authentication with URL-encoded credentials**: the connection URL with your encoded credentials:
       `https://{encoded_username}:{encoded_password}@mcp.onlyoffice.com/mcp?base_url=https://your-instance.onlyoffice.com`
        - Replace `{encoded_username}` with your URL-encoded ONLYOFFICE Apps email.
        - Replace `{encoded_password}` with your URL-encoded ONLYOFFICE Apps password.
        - Replace `your-instance.onlyoffice.com` with your actual ONLYOFFICE Apps domain.
6. Keep the detected authentication settings and click **Add**:
    - For OAuth: **Sign in now** and **Register automatically**.
    - For URL-encoded credentials: **No sign-in**.
7. Click **Connect**.
8. If you chose OAuth, complete the authentication process:
    - Sign in to your ONLYOFFICE Apps account by entering your email and password and clicking **Sign In**.
    - If you have more than one account associated with the entered email, choose one of them.
    - Allow the MCP Remote Server to access the specified data in your ONLYOFFICE Apps account.

   The connector page shows the **Disconnect** button and the list of tool permissions.

> **Note:** Connectors are linked to your Claude account. A connector added in Claude Web is also available in Claude Desktop, and vice versa. On the Claude Free plan, you can add only one custom connector. To remove a connector, click its name in the **Connectors** list, click **⋮**, and select **Remove**.

### Encode credentials for the URL

> **Note:** Credentials in the URL are stored in the connector settings and are visible to anyone who opens them. They may also be logged in browser history or network monitoring tools. Use this method only for testing, and prefer OAuth for regular use.

To encode your credentials:

- Encode the `@` symbol in your email as `%40` (e.g., `username%40example.com`).
- Encode special characters in your password (e.g., `!` becomes `%21`, `#` becomes `%23`).
- To encode a value without sending it anywhere, open a new browser tab, open the developer tools (F12), go to the **Console** tab, and run `encodeURIComponent("your-value")`.

## Connect to Cursor

Cursor allows you to connect to the ONLYOFFICE Apps MCP server either via:

- (Recommended) [HTTP](#connect-cursor-to-remote-onlyoffice-apps-mcp-server-via-http) 
- [Command](#connect-cursor-to-local-onlyoffice-apps-mcp-server-via-command)

### Connect Cursor to remote ONLYOFFICE Apps MCP server via HTTP

Connect to the MCP server running remotely using Streamable-HTTP transport.

1. Open Cursor.
2. Bring up Command Palette and select **Open MCPs**.
3. Click **New MCP Server**. Cursor opens the `~/.cursor/mcp.json` file.
4. Add the `onlyoffice-apps` record to the `mcpServers` section:
   ```json
   {
     "mcpServers": {
       "onlyoffice-apps": {
         "type": "http",
         "url": "https://mcp.onlyoffice.com/mcp"
       }
     }
   }
   ```
5. Save the file. The server appears under **Needs Attention** with the **Needs authentication** status.
6. Click **Authenticate** next to **onlyoffice-apps**.
7. Complete the OAuth authentication process in your browser:
    - Sign in to your ONLYOFFICE Apps account by entering your email and password and clicking **Sign In**.
    - If you have more than one account associated with the entered email, choose one of them.
    - Allow the MCP Remote Server to access the specified data in your ONLYOFFICE Apps account.
    - When the browser asks to open Cursor, click **Open Cursor**.

   The server moves to the **Connected** list and shows the number of enabled tools.
    
### Connect Cursor to local ONLYOFFICE Apps MCP server via command

Connect to the locally running MCP server using stdio transport.

> **Tip:** You can also add the server to Cursor in one click using the [Quick install](installation.md#quick-install) buttons.

1. Open Cursor.
2. Bring up Command Palette and select **Open MCPs**.
3. Click **New MCP Server**. Cursor opens the `~/.cursor/mcp.json` file.
4. Add the `onlyoffice-apps` record to the `mcpServers` section and replace the `DOCSPACE_BASE_URL` and `DOCSPACE_API_KEY` values with your own:
   ```json
   {
     "mcpServers": {
       "onlyoffice-apps": {
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

   The server appears in the **Connected** list and shows the number of enabled tools.

## Connect to Mistral Vibe

> **Note:** In May 2026, Mistral renamed Le Chat to Mistral Vibe.

1. Open [Mistral Vibe](https://chat.mistral.ai) in your web browser.
2. Navigate to **Context** → **Connectors**.
3. Click **Add connector**, and then click **Add a custom connector**.
4. Enter a name for the connector (e.g., `ONLYOFFICE_Apps_MCP`). Spaces are not allowed, so use underscores instead.
5. Enter the server URL based on your preferred authentication method:
    - **OAuth**: `https://mcp.onlyoffice.com/mcp`
    - **API token**: `https://mcp.onlyoffice.com/mcp?base_url=https://your-instance.onlyoffice.com`. Replace `your-instance.onlyoffice.com` with your actual ONLYOFFICE Apps domain.
6. Select the authentication method in the **Authentication** section:
    - **OAuth**: Mistral Vibe detects **OAuth2.1** automatically. To use your own [ONLYOFFICE Apps OAuth application](https://api.onlyoffice.com/docspace/api-backend/get-started/authentication/oauth2/creating-oauth-app/), turn on **Advanced OAuth Settings** and enter the application's **Client ID** and **Client Secret**. When creating the application:
        - Add `https://mcp.onlyoffice.com/oauth/callback` to **Redirects URLs**. You do not need to add the **Redirect URI** shown by Mistral Vibe.
        - Add `https://mcp.onlyoffice.com` to **Allowed origins**.
        - Select the **Write** access for **Profile**, **Contacts**, **Rooms**, and **Files & Folders**, and select **Open ID**.
    - **API token**: Select **API Token Authentication**, keep **Bearer**, and enter your personal API key generated in ONLYOFFICE Apps **Developer Tools** → **API keys** in the **Authorization header value** field.
7. Click **Add connector**.
8. If you chose OAuth, complete the OAuth authentication process:
    - Sign in to your ONLYOFFICE Apps account by entering your email and password and clicking **Sign In**.
    - If you have more than one account associated with the entered email, choose one of them.
    - Allow the application to access the specified data in your ONLYOFFICE Apps account.

   The connector page shows the connection with the **Valid** status and the list of tools.
9. Click **Try now** to open a new chat with the connector selected.

## Connect to VS Code

VS Code client also connects to ONLYOFFICE Apps MCP server using:

- [HTTP](#connect-vs-code-to-remote-onlyoffice-apps-mcp-server-via-http)
- [Command](#connect-vs-code-to-local-onlyoffice-apps-mcp-server-via-command)

### Connect VS Code to remote ONLYOFFICE Apps MCP server via HTTP

This is the preferred connection method and connects to the remote MCP server using Streamable-HTTP transport. 

1. Open Visual Studio Code.
2. Bring up Command Palette and select **MCP: Open User Configuration**. VS Code opens the `mcp.json` file.
3. Add the `onlyoffice-apps` record to the `servers` section:
   ```json
   {
     "servers": {
       "onlyoffice-apps": {
         "type": "http",
         "url": "https://mcp.onlyoffice.com/mcp"
       }
     }
   }
   ```
4. Save the file.
5. Click **Start** above the `onlyoffice-apps` record in the file.
6. When VS Code asks to authenticate to `mcp.onlyoffice.com`, click **Allow**, and then click **Open** to open the sign-in page in your browser.
7. Complete the OAuth authentication process:
    - Sign in to your ONLYOFFICE Apps account by entering your email and password and clicking **Sign In**.
    - If you have more than one account associated with the entered email, choose one of them.
    - Allow the MCP Remote Server to access the specified data in your ONLYOFFICE Apps account.
    - When the browser asks to open Visual Studio Code, click **Open Visual Studio Code**.

   The server status above the record changes to **Running** and shows the number of available tools.

### Connect VS Code to local ONLYOFFICE Apps MCP server via command

Connect to the locally running MCP server using stdio transport.

> **Tip:** You can also add the server to VS Code in one click using the [Quick install](installation.md#quick-install) buttons.

1. Open Visual Studio Code.
2. Bring up Command Palette and select **MCP: Open User Configuration**. VS Code opens the `mcp.json` file.
3. Add the `onlyoffice-apps` record to the `servers` section and replace the `DOCSPACE_BASE_URL` and `DOCSPACE_API_KEY` values with your own:
   ```json
   {
     "servers": {
       "onlyoffice-apps": {
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
4. Save the file.
5. Click **Start** above the `onlyoffice-apps` record in the file.

   The server status changes to **Running** and shows the number of available tools.

## Connect to Devin Desktop

> **Note:** In June 2026, Cognition renamed Windsurf to Devin Desktop.

Devin Desktop offers two ways to connect to the ONLYOFFICE Apps MCP server:

- [HTTP](#connect-devin-desktop-to-remote-onlyoffice-apps-mcp-server-via-http)
- [Command](#connect-devin-desktop-to-local-onlyoffice-apps-mcp-server-via-command)

### Connect Devin Desktop to remote ONLYOFFICE Apps MCP server via HTTP

This is the recommended method and connects to the remote MCP server using Streamable-HTTP transport.

1. Open Devin Desktop.
2. Bring up Command Palette and select **Devin: Devin MCP Registry**. The **Devin Customizations** tab opens.
3. Navigate to **MCPs** → **Available** and click **Add custom MCP**. Devin Desktop opens the `mcp_config.json` file.
4. Add the `onlyoffice-apps` record to the `mcpServers` section based on your preferred authentication method:
    - **OAuth**:
      ```json
      {
        "mcpServers": {
          "onlyoffice-apps": {
            "serverUrl": "https://mcp.onlyoffice.com/mcp"
          }
        }
      }
      ```
    - **API key**: Replace the `X-Mcp-Base-Url` and `X-Mcp-Api-Key` values with your ONLYOFFICE Apps URL and API key:
      ```json
      {
        "mcpServers": {
          "onlyoffice-apps": {
            "serverUrl": "https://mcp.onlyoffice.com/mcp",
            "headers": {
              "X-Mcp-Base-Url": "https://your-instance.onlyoffice.com",
              "X-Mcp-Api-Key": "your-api-key"
            }
          }
        }
      }
      ```
5. Save the file. The server appears in **MCPs** → **Installed**.
6. Connect the server:
    - **OAuth**: Click **Authenticate** next to **onlyoffice-apps** and complete the OAuth authentication process:
        - Sign in to your ONLYOFFICE Apps account by entering your email and password and clicking **Sign In**.
        - If you have more than one account associated with the entered email, choose one of them.
        - Allow the MCP Remote Server to access the specified data in your ONLYOFFICE Apps account.
    - **API key**: Click **onlyoffice-apps** to open the server page, and then click **Connect**.

   The server status changes to **Connected**, and the list of available tools is displayed.

### Connect Devin Desktop to local ONLYOFFICE Apps MCP server via command

This method uses stdio transport to connect to a locally running MCP server.

1. Open Devin Desktop.
2. Bring up Command Palette and select **Devin: Devin MCP Registry**. The **Devin Customizations** tab opens.
3. Navigate to **MCPs** → **Available** and click **Add custom MCP**. Devin Desktop opens the `mcp_config.json` file.
4. Add the `onlyoffice-apps` record to the `mcpServers` section and replace the `DOCSPACE_BASE_URL` and `DOCSPACE_API_KEY` values with your own:
   ```json
   {
     "mcpServers": {
       "onlyoffice-apps": {
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
5. Save the file. The server appears in **MCPs** → **Installed**.
6. Click **onlyoffice-apps** to open the server page, and then click **Connect**.

   The server status changes to **Connected**, and the list of available tools is displayed.

When the agent calls an ONLYOFFICE Apps tool in a Devin Local session, click **Allow** in the **Permission required** prompt.
