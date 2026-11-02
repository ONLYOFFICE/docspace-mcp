# ONLYOFFICE Apps

Connects an AI agent to [ONLYOFFICE Apps], a room-based collaborative platform,
so it can organize rooms, folders, and files and work with documents on your
portal from the conversation, without switching to the browser.

## What's Included

This plugin connects the agent to the hosted ONLYOFFICE Apps MCP server
(`https://mcp.onlyoffice.com/mcp`), with no local Node.js, npm, or Docker
required. It is described twice, once per format, and both describe the same
server:

| Format                | Location                                  | Read by                                    |
| --------------------- | ----------------------------------------- | ------------------------------------------ |
| [Agent Plugins]       | `plugin.json`, `mcp.json`                 | Codex, the ChatGPT desktop app, and others |
| [Claude Code plugins] | `.claude-plugin/plugin.json`, `.mcp.json` | Claude Code                                |

## Installation

The plugin is listed in the [ONLYOFFICE Agent Plugins] marketplace. Add the
marketplace and install the plugin with your agent's plugin command:

```bash
<your-agent> plugin marketplace add ONLYOFFICE/agent-plugins
<your-agent> plugin install onlyoffice-apps@onlyoffice
```

## Usage Examples

- "Create a room for the marketing team and invite John Smith as an editor"
- "Write meeting notes from my bullet points and save them to the Team room"
- "Summarize the latest report in the Projects room"

## Privacy Policy

The policies are available at [Legal Terms] and [Privacy Policy].

## License

The ONLYOFFICE Apps MCP server is distributed under the MIT license found in the
[LICENSE] file.

<!-- Footnotes -->

[ONLYOFFICE Apps]: https://www.onlyoffice.com/docspace.aspx
[ONLYOFFICE Agent Plugins]: https://github.com/ONLYOFFICE/agent-plugins
[Agent Plugins]: https://agent-plugins.org/
[Claude Code plugins]: https://code.claude.com/docs/en/plugins
[Legal Terms]: https://www.onlyoffice.com/legalterms
[Privacy Policy]: https://www.onlyoffice.com/privacy
[LICENSE]: https://github.com/ONLYOFFICE/docspace-mcp/blob/main/LICENSE
