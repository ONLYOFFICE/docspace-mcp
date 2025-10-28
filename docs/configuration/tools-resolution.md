# Tools Resolution

This document describes how the DocSpace MCP server resolves which tools are
available based on toolset configuration and enabled/disabled tool options.

## Contents

- [Visualization](#visualization)
	- [Global Configuration](#global-configuration)
	- [Request Configuration](#request-configuration)
- [Examples](#examples)
	- [Enable a Tool From Not Specified Toolset](#enable-a-tool-from-not-specified-toolset)
	- [Disable a Tool From Specified Toolset](#disable-a-tool-from-specified-toolset)
	- [Manually Specify Tools to Be Available](#manually-specify-tools-to-be-available)
- [References](#references)

## Visualization

The tools resolution process follows a sequence that starts with toolsets, adds
explicitly enabled tools, and removes explicitly disabled tools. The flowcharts
below illustrate this process for both global and request-level configuration.

### Global Configuration

During server initialization, the global configuration determines the baseline
set of available tools.

```mermaid
flowchart TD
	A[Load configuration] --> B{Are there any toolsets?}
	B -->|No| D[Start without tools]
	B -->|Yes| C[Initialize toolset iterator]
	C --> E[Get the next toolset]
	E --> F{Is the toolset known?}
	F -->|No| G[Error: Unknown toolset]
	F -->|Yes| H[Enable all tools from the toolset]
	H --> I{Are there more toolsets?}
	I -->|No| J{Are there any enabled tools?}
	I -->|Yes| E
	D --> J
	J -->|No| L{Are there any disabled tools?}
	J -->|Yes| K[Initialize enabled tools iterator]
	K --> K1[Get the next enabled tool]
	K1 --> K2{Is the tool known?}
	K2 -->|No| K3[Error: Unknown enabled tool]
	K2 -->|Yes| K4[Enable the tool]
	K4 --> K5{Are there more enabled tools?}
	K5 -->|No| L
	K5 -->|Yes| K1
	L -->|No| N[Tools are ready]
	L -->|Yes| M[Initialize disabled tools iterator]
	M --> M1[Get the next disabled tool]
	M1 --> M2{Is the tool known?}
	M2 -->|No| M3[Error: Unknown disabled tool]
	M2 -->|Yes| M4{Is the tool enabled?}
	M4 -->|No| M6[Skip: Ignore the tool]
	M4 -->|Yes| M5[Disable the tool]
	M5 --> M7{Are there more disabled tools?}
	M6 --> M7
	M7 -->|No| N
	M7 -->|Yes| M1
```

### Request Configuration

For HTTP-like transports, request-specific headers can override the global tool
configuration using the same resolution process. However, the available toolsets
and tools are constrained by what was configured globally.

## Examples

For simplicity, let us come up with a small list of available toolsets and
tools. The real DocSpace MCP server provides more of them, but for these
examples, just a few are enough:

| Toolset   | Tools                                          |
| --------- | ---------------------------------------------- |
| `files`   | `create_file`, `get_file`, `delete_file`       |
| `folders` | `create_folder`, `get_folder`, `delete_folder` |

### Enable a Tool From Not Specified Toolset

Configuration:

| Key           | Value           |
| ------------- | --------------- |
| Toolsets      | `files`         |
| Enabled Tools | `create_folder` |

Result:

| Toolset   | Tools                                    |
| --------- | ---------------------------------------- |
| `files`   | `create_file`, `get_file`, `delete_file` |
| `folders` | `create_folder`                          |

### Disable a Tool From Specified Toolset

Configuration:

| Key            | Value           |
| -------------- | --------------- |
| Toolsets       | `files`         |
| Enabled Tools  | `create_folder` |
| Disabled Tools | `get_file`      |

Result:

| Toolset   | Tools                        |
| --------- | ---------------------------- |
| `files`   | `create_file`, `delete_file` |
| `folders` | `create_folder`              |

### Manually Specify Tools to Be Available

Configuration:

| Key            | Value                                      |
| -------------- | ------------------------------------------ |
| Toolsets       | (empty, to disable all tools)              |
| Enabled Tools  | `create_file`, `get_file`, `create_folder` |
| Disabled Tools | `get_file`, `delete_folder`                |

Result:

| Toolset   | Tools           |
| --------- | --------------- |
| `files`   | `create_file`   |
| `folders` | `create_folder` |

## References

- [DocSpace MCP: Global Configuration]
- [DocSpace MCP: Request Configuration]

<!-- Footnotes -->

[DocSpace MCP: Global Configuration]: ./global-configuration.md
[DocSpace MCP: Request Configuration]: ./request-configuration.md
