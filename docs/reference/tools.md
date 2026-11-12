# Tools

The ONLYOFFICE Apps MCP server implements the Tools concept from the MCP specification.

## Toolsets

A toolset is an ONLYOFFICE Apps MCP server extension to the standard MCP Tools concept.
Toolsets provide logical grouping of related tools to organize
ONLYOFFICE Apps functionality into manageable categories.

<!--generate toolsets-start-->

| #   | Toolset Name | Toolset Description                                                                           |
| --- | ------------ | --------------------------------------------------------------------------------------------- |
| 1   | `files`      | Operations for working with files.                                                            |
| 2   | `folders`    | Operations for working with folders, including the 'Files' section (formerly 'My Documents'). |
| 3   | `people`     | Operations for working with users.                                                            |
| 4   | `rooms`      | Operations for working with rooms.                                                            |

<!--generate toolsets-end-->

## Regular tools

Regular tools are standard MCP Tools. Each tool corresponds to a specific
ONLYOFFICE Apps operation.

<!--generate tools-start-->

### Files toolset

| #   | Tool Name                  | Tool Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| --- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | `copy_batch_items`         | Copy to a folder.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| 2   | `delete_file`              | Delete a file.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| 3   | `download_file_as_text`    | Download a file as text.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| 4   | `get_file_info`            | Get file information.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| 5   | `get_office_api_reference` | Look up the Office JavaScript API that run_builder_script scripts are written against. Use it before every run_builder_script call to check the methods the script uses, since the API changes between versions and remembered signatures may be outdated. Without class and query, returns an overview of the editor API with the list of its classes and enumerations; with query, finds classes, methods and enumerations; with class, returns the methods of a class or the values of an enumeration; with class and method, returns the syntax, parameters and an example of a method. The reference is read from api.onlyoffice.com. |
| 6   | `move_batch_items`         | Move to a folder.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| 7   | `prepare_local_upload`     | Reserve a local file path for one upload_local_file call. Save the file to the returned path exactly as it is, without adding an extension, then pass the returned fileId and the file name to upload_local_file. Call it before every upload: each path is used once. All paths are in the same directory.                                                                                                                                                                                                                                                                                                                                |
| 8   | `run_builder_script`       | Run an ONLYOFFICE Document Builder script to create or edit documents, spreadsheets, presentations or PDFs, and wait for it to finish. The Office JavaScript API changes between versions (since 9.4.0, for example, Api.CreateTable takes rows before columns), so do not write the script from memory: look up every class and method it uses with the get_office_api_reference tool first. Returns the saved files in the files field; a file may get a different title than the name passed to builder.SaveFile when the folder already has a file with that name.                                                                     |
| 9   | `update_file`              | Update a file.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| 10  | `upload_file`              | Upload a file.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| 11  | `upload_local_file`        | Upload a file of any format, including binary, saved to the path that prepare_local_upload returned, under the given file name. The local file is removed once it is uploaded.                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

> **Note:** The `upload_file` tool supports only text formats, such as `txt` and `md`. The `upload_local_file` tool uploads files of any format, including binary, through a local exchange directory and is available only on the stdio transport.

### Folders toolset

| #   | Tool Name            | Tool Description                                  |
| --- | -------------------- | ------------------------------------------------- |
| 12  | `create_folder`      | Create a folder.                                  |
| 13  | `delete_folder`      | Delete a folder.                                  |
| 14  | `get_folder_content` | Get content of a folder.                          |
| 15  | `get_folder_info`    | Get folder information.                           |
| 16  | `get_my_folder`      | Get the 'Files' folder (formerly 'My Documents'). |
| 17  | `rename_folder`      | Rename a folder.                                  |

### People toolset

| #   | Tool Name        | Tool Description |
| --- | ---------------- | ---------------- |
| 18  | `get_all_people` | Get all people.  |

### Rooms toolset

| #   | Tool Name                | Tool Description                                        |
| --- | ------------------------ | ------------------------------------------------------- |
| 19  | `archive_room`           | Archive a room.                                         |
| 20  | `create_room`            | Create a room.                                          |
| 21  | `get_room_access_levels` | Get a list of available room invitation access levels.  |
| 22  | `get_room_info`          | Get room information.                                   |
| 23  | `get_room_security_info` | Get a list of users with their access levels to a room. |
| 24  | `get_room_types`         | Get a list of available room types.                     |
| 25  | `get_rooms_folder`       | Get the 'Rooms' folder.                                 |
| 26  | `set_room_security`      | Invite or remove users from a room.                     |
| 27  | `update_room`            | Update a room.                                          |

<!--generate tools-end-->

## Meta tools

Meta tools are an ONLYOFFICE Apps MCP server extension to the standard MCP Tools
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
