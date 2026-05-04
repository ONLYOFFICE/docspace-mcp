# Troubleshooting issues with Le Chat MCP client

The following issues can occur when connecting the DocSpace MCP server to the Le Chat client.

## The "Custom MCP Connector" option is not available

The Custom MCP Connector feature may require a paid Le Chat subscription or may not yet be available in your region. To fix:

- Verify that your Le Chat account plan includes access to custom MCP connectors.
- Check the [Le Chat documentation](https://chat.mistral.ai) for the latest information on feature availability.

## Multiple accounts appear during sign-in but selection has no effect

A session or cookie conflict may be preventing the correct account from being selected. Try any of these fixes:

- Clear your browser cookies and cache, then repeat the OAuth flow.
- Try signing in using a private/incognito browser window.

## Access is not granted after completing authentication

The permission consent step may have been skipped or declined. Follow these steps to fix:

1. Repeat the [connection process](../getting-started/clients.md#connect-to-le-chat) from step 9.
2. On the final OAuth screen, make sure to click **Allow** (or equivalent) to grant the MCP server access to your DocSpace account.
3. If the consent screen does not appear, revoke the existing OAuth token in your DocSpace account settings and try again.

## The connector appears in Le Chat but DocSpace tools are not called

After a successful connection, the DocSpace connector must be explicitly enabled in the **Tools** window for each conversation. If it is not selected, Le Chat will not invoke any DocSpace tools even though the connector is configured correctly. To fix:

1. Open the **Tools** panel in Le Chat.
2. In the **Connectors** list, make sure **ONLYOFFICE_DocSpace_MCP** (or the name you assigned) is selected.
3. Start a new conversation and try again.

## The connector appears in Le Chat but returns no data

The MCP server connection may have been established, but the OAuth token has expired or the connector is misconfigured. Retry any of these solutions to fix:

- Remove the existing connector in Le Chat and retry [adding it](../getting-started/clients.md#connect-to-le-chat).
- Check that the server URL is `https://mcp.onlyoffice.com/mcp` and that **OAuth2.1** is selected as the authentication method.
- Contact your DocSpace administrator to verify that the MCP server is running and accessible.
