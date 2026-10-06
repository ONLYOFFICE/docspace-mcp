# Troubleshooting issues with Mistral Vibe MCP client

The following issues can occur when connecting the ONLYOFFICE Apps MCP server to the Mistral Vibe client (formerly Le Chat).

## The "Add a custom connector" option is not available

In Mistral Vibe, custom connectors are added from the connector marketplace. To find the option:

1. Navigate to **Context** → **Connectors**.
2. Click **Add connector**. The **Marketplace** page opens.
3. Click **Add a custom connector**.

If the option is still not available, check the [Mistral Vibe documentation](https://chat.mistral.ai) for the latest information on feature availability.

## Multiple accounts appear during sign-in but selection has no effect

A session or cookie conflict may be preventing the correct account from being selected. Try any of these fixes:

- Clear your browser cookies and cache, then repeat the OAuth flow.
- Try signing in using a private/incognito browser window.

## Access is not granted after completing authentication

The permission consent step may have been skipped or declined. Follow these steps to fix:

1. Repeat the [connection process](../getting-started/clients.md#connect-to-mistral-vibe) from step 8.
2. On the final OAuth screen, make sure to click **Allow** (or equivalent) to grant the MCP server access to your ONLYOFFICE Apps account.
3. If the consent screen does not appear, revoke the existing OAuth token in your ONLYOFFICE Apps account settings and try again.

## The connector appears in Mistral Vibe but ONLYOFFICE Apps tools are not called

The connector must be selected in the conversation. If it is not selected, Mistral Vibe does not invoke any ONLYOFFICE Apps tools even though the connector is configured correctly. To fix:

1. Navigate to **Context** → **Connectors** and click the connector name (e.g., **ONLYOFFICE_Apps_MCP**).
2. Click **Try now**. Mistral Vibe opens a new chat with the connector selected in the message field.
3. Send your request again.

## The connector appears in Mistral Vibe but returns no data

The MCP server connection may have been established, but the OAuth token has expired or the connector is misconfigured. Retry any of these solutions to fix:

- Delete the existing connector (click its name, click **⋮**, and select **Delete**) and retry [adding it](../getting-started/clients.md#connect-to-mistral-vibe).
- Check that the server URL is `https://mcp.onlyoffice.com/mcp` and that **OAuth2.1** is selected as the authentication method.
- Contact your ONLYOFFICE Apps administrator to verify that the MCP server is running and accessible.
