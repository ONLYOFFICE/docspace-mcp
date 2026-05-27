# Tools

The DocSpace MCP server implements the Tools concept from the MCP specification.

## Toolsets

A toolset is a DocSpace MCP server extension to the standard MCP Tools concept.
Toolsets provide logical grouping of related tools to organize
DocSpace functionality into manageable categories.

<!--generate toolsets-start-->

| #   | Toolset Name | Toolset Description                  |
| --- | ------------ | ------------------------------------ |
| 1   | `files`      | Operations for working with files.   |
| 2   | `folders`    | Operations for working with folders. |
| 3   | `people`     | Operations for working with users.   |
| 4   | `rooms`      | Operations for working with rooms.   |

<!--generate toolsets-end-->

## Regular tools

Regular tools are standard MCP Tools. Each tool corresponds to a specific
DocSpace operation.

<!--generate tools-start-->

### Files toolset

| #   | Tool Name              | Tool Description        |
| --- | ---------------------- | ----------------------- |
| 1   | `copy_batch_items`     | Copy to a folder.       |
| 2   | `delete_file`          | Delete a file.          |
| 3   | `download_file_as_text`| Download a file as text.|
| 4   | `get_file_info`        | Get file information.   |
| 5   | `move_batch_items`     | Move to a folder.       |
| 6   | `update_file`          | Update a file.          |
| 7   | `upload_file`          | Upload a file.          |

> **Note:** Supported file formats for uploading: `txt`, `md`.

### Folders toolset

| #   | Tool Name            | Tool Description                   |
| --- | -------------------- | ---------------------------------- |
| 8   | `create_folder`      | Create a folder.                   |
| 9   | `delete_folder`      | Delete a folder.                   |
| 10  | `get_folder_content` | Get content of a folder.           |
| 11  | `get_folder_info`    | Get folder information.            |
| 12  | `get_my_folder`      | Get the 'My Documents' folder.     |
| 13  | `rename_folder`      | Rename a folder.                   |

### People toolset

| #   | Tool Name        | Tool Description |
| --- | ---------------- | ---------------- |
| 14  | `get_all_people` | Get all people.  |

### Rooms toolset

| #   | Tool Name                | Tool Description                                          |
| --- | ------------------------ | --------------------------------------------------------- |
| 15  | `archive_room`           | Archive a room.                                           |
| 16  | `create_room`            | Create a room.                                            |
| 17  | `get_room_access_levels` | Get a list of available room invitation access levels.    |
| 18  | `get_room_info`          | Get room information.                                     |
| 19  | `get_room_security_info` | Get a list of users with their access levels to a room.   |
| 20  | `get_room_types`         | Get a list of available room types.                       |
| 21  | `get_rooms_folder`       | Get the 'Rooms' folder.                                   |
| 22  | `set_room_security`      | Invite or remove users from a room.                       |
| 23  | `update_room`            | Update a room.                                            |

<!--generate tools-end-->

## Meta tools

Meta tools are a DocSpace MCP server extension to the standard MCP Tools
concept. They provide a dynamic interface for tool discovery and execution,
allowing AI models to interact with tools without requiring all tools to be
loaded simultaneously.

When enabled, regular tools are wrapped into meta tools. Meta tools work in
conjunction with the same toolset and tool configuration options as regular
tools, providing the same level of control over available functionality.

<!--generate meta-tools-start-->

| #   | Meta Tool Name           | Meta Tool Description                                                                                                                                                                           |
| --- | ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `call_tool`              | This is a meta tool for calling a tool. The list of available tools can be obtained using the list_tools meta tool. The input schema can be obtained using the get_tool_input_schema meta tool. |
| 2   | `get_tool_input_schema`  | This is a meta tool for getting an input schema for a specific tool. The list of available tools can be obtained using the list_tools meta tool.                                                |
| 3   | `get_tool_output_schema` | This is a meta tool for getting an output schema for a specific tool. The list of available tools can be obtained using the list_tools meta tool.                                               |
| 4   | `list_tools`             | This is a meta tool for listing available tools of a specific toolset. The list of available toolsets can be obtained using the list_toolsets meta tool.                                        |
| 5   | `list_toolsets`          | This is a meta tool for listing available toolsets. Toolset is a set of available tools.                                                                                                        |

<!--generate meta-tools-end-->


## Resolving tools

The tools resolution process follows a sequence that starts with toolsets, adds explicitly enabled tools, and removes explicitly disabled tools. For the full flowcharts and worked examples, see [Tools resolution](./tools-resolution.md).
