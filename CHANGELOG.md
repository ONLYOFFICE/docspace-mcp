# Changelog

This document records all notable changes to the project, following the [Keep a Changelog] format and adhering to [Semantic Versioning].

## [Unreleased]

<!-- There are no noticeable changes in version [unreleased]. -->

### Add

- Add partial support for output schemas ([b50a7bc]);
- Add the implementation of SSE transport ([9b3535c], [2504af1], [d63057b]);
- Add the implementation of Streamable HTTP transport ([b1fe294], [2504af1], [d63057b]);
- Add the implementation of OAuth2 protocol ([b1fe294]);
- Add the ability to configure using HTTP headers ([785f5dc]);
- Add support for the logging capability ([ce30d96]).

### Changed

- In the internal Streamable HTTP transport, check `Authorization` and `Referer` headers only during the initialization request ([b6e33bf]);
- Update `@modelcontextprotocol/sdk` to 1.17.0 ([8d3f3f3]);
- Ignore the `DOCSPACE_TRANSPORT` option when the `DOCSPACE_INTERNAL` option is set ([d643a82]);
- **Breaking** Remove the `DOCSPACE_ORIGIN` option ([ac33ab6]);
- Downgrade the minimum required Node.js version to 18.0.0 ([6ac1d59]).

### Fixed

- Restore access to regular tools when using meta-tools ([eb84c1f]);
- Prevent a disabled tool from being called when a regular tool is called ([eb84c1f]);
- In the internal Streamable HTTP transport, allow the `Referer` header to be without a trailing slash ([ad70531]);
- Require the `DOCSPACE_HOST` option to be present when the `DOCSPACE_TRANSPORT` is set to an HTTP-like transport ([428ee1c]);
- When the `DOCSPACE_TRANSPORT` option is set to `stdio`, validate the `DOCSPACE_BASE_URL` only if `DOCSPACE_API_KEY`, `DOCSPACE_AUTH_TOKEN`, or `DOCSPACE_USERNAME`/`DOCSPACE_PASSWORD` is present ([428ee1c]);
- Better validate the `DOCSPACE_BASE_URL` option ([428ee1c]);
- The `DOCSPACE_SESSION_TTL` option with the `0` value prevents session expiration ([428ee1c]);
- The `DOCSPACE_SESSION_INTERVAL` option with the `0` value disables session cleanup ([428ee1c]);
- Make `DOCSPACE_API_KEY`, `DOCSPACE_AUTH_TOKEN`, and `DOCSPACE_USERNAME`/`DOCSPACE_PASSWORD` trimmable ([428ee1c]);
- The `DOCSPACE_PORT` option with the `0` value selects a random port ([428ee1c]);
- Allow the `65535` value for the `DOCSPACE_PORT` option ([428ee1c]);
- For all options with the boolean type, the empty string value resolves to the `false` value ([428ee1c]);
- For all options with the number type, the empty string value resolves to the `0` value ([428ee1c]);
- For the `get_file_info` and `update_file` tools, fix the type of the `folderId` field in the response ([2cde131]).

## [2.0.0] - 2025-07-23

### Added

- Add an internal implementation of Streamable HTTP transport ([ca3a432]);
- Add the ability to enable and disable tools ([74ac987]).

### Changed

- Replace `anyOf` with `enum` in JSON schemas ([9d35a14]);
- Gracefully handle SIGTERM and SIGINT signals ([ca3a432]);
- Use native basic authentication ([fcd203a]);
- Update `@modelcontextprotocol/sdk` to 1.16.0 ([2c0f50f]);
- **Breaking** Remove unclaimed tools: `files_get_folders`, `files_get_operation_statuses`, `portal_get_quota`, `portal_get_tariff`, `settings_get_supported_cultures`, `settings_get_time_zones` ([1eb7792]);
- **Breaking** Rename all tools and reorganize all toolsets ([90c2b72]).

### Fixed

- Remove hardcoded extensions from the `others_download_as_text` tool ([0d657d9]).

## [1.3.1] - 2025-07-08

### Changed

- Start the server even if it is misconfigured ([a6b4e85]).

### Fixed

- Verify that at least one of the authentication methods is set ([0ea66c8]).

## [1.3.0] - 2025-07-01

### Added

- Add more filters for tools `get_folder`, `files_get_my_folder`, `files_get_room_security_info`, `files_get_rooms_folder`, and `people_get_all` ([6d36beb]).

### Changed

- Remove string literals from `RoomType`, `FileShare`, and `FileType` schemas ([6d36beb], [97e1454]).

### Fixed

- Fix handling error responses with a non-JSON body ([7e9be5d]).
- Remove invalid filters from tools `get_folder`, `files_get_my_folder`, `files_set_room_security`, `files_get_room_security_info`, `files_get_rooms_folder`, and `people_get_all_tool` ([6d36beb]).

## [1.2.0] - 2025-06-24

### Added

- Add `fields` filter to `files_get_file_info`, `files_create_folder`, `files_get_folder`, `files_get_folder_info`, `files_get_folders`, `files_rename_folder`, `files_get_my_folder`, `files_create_room`, `files_get_room_info`, `files_update_room`, `files_set_room_security`, `files_get_room_security_info`, `files_get_rooms_folder`, and `people_get_all` tools ([88f0581]).
- Add general filters to `files_set_room_security` and `files_get_room_security_info` tools ([88f0581]).
- Add `DOCSPACE_DYNAMIC` and `DOCSPACE_TOOLSETS` options ([8e2e54a]).

### Changed

- Rename tool `others_get_available_room_invitation_access` to `others_get_available_room_access` ([cf92803]).
- Require the `count` filter field be in the range from 1 to 50 ([ae0c83a]).
- Make all filters mandatory ([756fd7b]).

## [1.1.0] - 2025-06-02

### Added

- Add the filters option to the `files_get_rooms_folder` tool ([ecb261e]).
- Add the filters option to the `people_get_all` tool ([97e4d73]).

### Changed

- Change the default `filters.count` value to `30` for the `files_get_folder` tool ([036098d]).

## [1.0.0] - 2025-05-13

### Changed

- Clarify that the room invitation access level may vary depending on the room type ([52afde9], [ded370e]).
- Clarify the names of the room types in their descriptions ([77aa941]).

## [0.2.0] - 2025-05-07

### Added

- Add the `settings_get_supported_cultures` tool ([c443470], [ea5e530]).
- Add the `settings_get_time_zones` tool ([ce1b5b7], [8ebac70]).
- Add the `portal_get_tariff` tool ([c52624d], [2812396]).
- Add the `portal_get_quota` tool ([91e7cd8], [c0069de]).
- Add the `others_get_available_room_types` tool ([ec8948c]).
- Add the `others_get_available_room_invitation_access` tool ([50ff80a]).

### Changed

- Expand the input for the `files_set_room_security` tool ([0fec2b5], [5af63c3]).
- Rephrase descriptions of the inputs of tools ([06934e6]).

### Fixed

- Fix the calculation of the filesize for the `others_upload_file` tool ([8a129ad]).
- Add missing input options for the `files_update_room` tool ([7750110]).
- Handle an error response with status 200 when uploading a chunk ([7e0ff48]).

## [0.1.3] - 2025-04-24

### Fixed

- Fix compatibility with Windsurf Editor ([c637742], [3ae9500]).

## [0.1.2] - 2025-04-23

### Fixed

- Fix the hashbang for the bin file ([90745be]).

## [0.1.1] - 2025-04-23

### Fixed

- Fix the path to the bin file ([e3e04c7]).

## [0.1.0] - 2025-04-23

### Added

- The `DOCSPACE_BASE_URL`, `DOCSPACE_ORIGIN`, `DOCSPACE_USER_AGENT`, `DOCSPACE_API_KEY`, `DOCSPACE_AUTH_TOKEN`, `DOCSPACE_USERNAME`, `DOCSPACE_PASSWORD` configuration options.
- The `files.archive_room`, `files.copy_batch_items`, `files.create_folder`, `files.create_room`, `files.delete_file`, `files.delete_folder`, `files.get_file_info`, `files.get_folder`, `files.get_folder_info`, `files.get_folders`, `files.get_my_folder`, `files.get_operation_statuses`, `files.get_room_info`, `files.get_room_security_info`, `files.get_rooms_folder`, `files.move_batch_items`, `files.rename_folder`, `files.set_room_security`, `files.update_file`, `files.update_room`, `others.download_as_text`, `others.upload_file`, `people.get_all` tools.

<!-- Footnotes -->

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html

[Unreleased]: https://github.com/onlyoffice/docspace-mcp/compare/v2.0.0...HEAD/
[2.0.0]: https://github.com/onlyoffice/docspace-mcp/compare/v1.3.1...v2.0.0/
[1.3.1]: https://github.com/onlyoffice/docspace-mcp/compare/v1.3.0...v1.3.1/
[1.3.0]: https://github.com/onlyoffice/docspace-mcp/compare/v1.2.0...v1.3.0/
[1.2.0]: https://github.com/onlyoffice/docspace-mcp/compare/v1.1.0...v1.2.0/
[1.1.0]: https://github.com/onlyoffice/docspace-mcp/compare/v1.0.0...v1.1.0/
[1.0.0]: https://github.com/onlyoffice/docspace-mcp/compare/v0.2.0...v1.0.0/
[0.2.0]: https://github.com/onlyoffice/docspace-mcp/compare/v0.1.3...v0.2.0/
[0.1.3]: https://github.com/onlyoffice/docspace-mcp/compare/v0.1.2...v0.1.3/
[0.1.2]: https://github.com/onlyoffice/docspace-mcp/compare/v0.1.1...v0.1.2/
[0.1.1]: https://github.com/onlyoffice/docspace-mcp/compare/v0.1.0...v0.1.1/
[0.1.0]: https://github.com/onlyoffice/docspace-mcp/releases/tag/v0.1.0/

[2cde131]: https://github.com/onlyoffice/docspace-mcp/commit/2cde131e7fa0dbb90c90f155f93e86faef0754cb/
[ce30d96]: https://github.com/onlyoffice/docspace-mcp/commit/ce30d9638886433444b8da2d6fc6525bfc0bca5e/
[6ac1d59]: https://github.com/onlyoffice/docspace-mcp/commit/6ac1d59639248efcbbffca1edb82328ba349fddb/
[785f5dc]: https://github.com/onlyoffice/docspace-mcp/commit/785f5dc2dd435150ff7ce4309700d041aa0621a1/
[428ee1c]: https://github.com/onlyoffice/docspace-mcp/commit/428ee1c39f62a0d2d6a93d350187b35c1578e762/
[ac33ab6]: https://github.com/onlyoffice/docspace-mcp/commit/ac33ab651271affc2de6293ea5e12353cd2fa3d8/
[d643a82]: https://github.com/onlyoffice/docspace-mcp/commit/d643a8289b3d3112a15a95c4da477113bcd4f750/
[d63057b]: https://github.com/onlyoffice/docspace-mcp/commit/d63057b57193b7a1d927f56e0da7be1755cb5366/
[ad70531]: https://github.com/onlyoffice/docspace-mcp/commit/ad70531288788dbdea452c71217384325734bcc2/
[2504af1]: https://github.com/onlyoffice/docspace-mcp/commit/2504af1459ce15980dc68366a8a9b3115a71948f/
[9b3535c]: https://github.com/onlyoffice/docspace-mcp/commit/9b3535cba408919d66d36878d218b9e53a8fae4d/
[b1fe294]: https://github.com/onlyoffice/docspace-mcp/commit/b1fe294f86506ab39d987057145142c7e66f76af/
[b6e33bf]: https://github.com/onlyoffice/docspace-mcp/commit/b6e33bfeedb13673374f38f8f846a574813a7876/
[8d3f3f3]: https://github.com/onlyoffice/docspace-mcp/commit/8d3f3f39b3cd99b1fd135881cc1bede193091a6a/
[b50a7bc]: https://github.com/onlyoffice/docspace-mcp/commit/b50a7bc2dc0a4554475e9f8f81a08ad7653870d5/
[eb84c1f]: https://github.com/onlyoffice/docspace-mcp/commit/eb84c1f7ebc16e5af646008b8fffacc51eb4e332/
[90c2b72]: https://github.com/onlyoffice/docspace-mcp/commit/90c2b72b7205173eabc81270f52778f6c6f16d7e/
[1eb7792]: https://github.com/onlyoffice/docspace-mcp/commit/1eb7792071515aba0706f8e0374c836c118b9a3f/
[2c0f50f]: https://github.com/onlyoffice/docspace-mcp/commit/2c0f50f354cda822537759756d7eef35e621d9e8/
[fcd203a]: https://github.com/onlyoffice/docspace-mcp/commit/fcd203ada86b2cd1a43ab7ad04602c60bd00b881/
[0d657d9]: https://github.com/onlyoffice/docspace-mcp/commit/0d657d9d35c819aeddf80ec58f8f6a18081b5f23/
[74ac987]: https://github.com/onlyoffice/docspace-mcp/commit/74ac987ea8e790058f3ca5dcf2da4087ba5671a3/
[ca3a432]: https://github.com/onlyoffice/docspace-mcp/commit/ca3a432764932abb7e5ff8e40667bff3a94b907f/
[9d35a14]: https://github.com/onlyoffice/docspace-mcp/commit/9d35a14cfd08181141b4c769f1ebaddd4754022d/
[a6b4e85]: https://github.com/onlyoffice/docspace-mcp/commit/a6b4e852d39d9247fd71843dc0fe7d374d78dde3/
[0ea66c8]: https://github.com/onlyoffice/docspace-mcp/commit/0ea66c84ddb9ee6899b093e64881a201d4601a4b/
[97e1454]: https://github.com/onlyoffice/docspace-mcp/commit/97e1454d28425b5549e4e0c7562d19e2136919c7/
[7e9be5d]: https://github.com/onlyoffice/docspace-mcp/commit/7e9be5dd0fc59c9dca2964a9588db914d020472c/
[6d36beb]: https://github.com/onlyoffice/docspace-mcp/commit/6d36beb94176e45acba35bd660e37294fc0fe22a/
[756fd7b]: https://github.com/onlyoffice/docspace-mcp/commit/756fd7bb8b97f6d0721b369fbcd265efe1a3686c/
[8e2e54a]: https://github.com/onlyoffice/docspace-mcp/commit/8e2e54a3f67647ea844047e90be189714baf677d/
[ae0c83a]: https://github.com/onlyoffice/docspace-mcp/commit/ae0c83aa87de4db1cf539547b866d656831eae94/
[88f0581]: https://github.com/onlyoffice/docspace-mcp/commit/88f058197e951b5451fb33378c5afed8164ff696/
[cf92803]: https://github.com/onlyoffice/docspace-mcp/commit/cf92803be37618cfef7bd1a313411ce775ea3cea/
[036098d]: https://github.com/onlyoffice/docspace-mcp/commit/036098db62ab4c4b29ab5e0b40c34ef1ced4efaa/
[97e4d73]: https://github.com/onlyoffice/docspace-mcp/commit/97e4d73bf6a740939e7b2223414ef82c45d4f8f0/
[ecb261e]: https://github.com/onlyoffice/docspace-mcp/commit/ecb261e0072f80bd6f989b813cc5f2823ac16c5d/
[77aa941]: https://github.com/onlyoffice/docspace-mcp/commit/77aa941cf0240d547d5c18a06dc26e26418313aa/
[ded370e]: https://github.com/onlyoffice/docspace-mcp/commit/ded370eb903008e6b8311d1e08604abe6ced464f/
[52afde9]: https://github.com/onlyoffice/docspace-mcp/commit/52afde93fdb637cd6b08af8564358ad95b25f99f/
[7e0ff48]: https://github.com/onlyoffice/docspace-mcp/commit/7e0ff480719118b0954e4cfcfc1a90d063f428c9/
[50ff80a]: https://github.com/onlyoffice/docspace-mcp/commit/50ff80a8ce87e4a838c6cb747fa927a284568242/
[ec8948c]: https://github.com/onlyoffice/docspace-mcp/commit/ec8948c271eb26eae2e953b886918afeb034215a/
[06934e6]: https://github.com/onlyoffice/docspace-mcp/commit/06934e6ae61256a619c8d01803047c019dac4048/
[7750110]: https://github.com/onlyoffice/docspace-mcp/commit/7750110bcbaa4590ede47f9fe3cc20a746046625/
[5af63c3]: https://github.com/onlyoffice/docspace-mcp/commit/5af63c36dc3f548bcf877171485574d53db0eb6b/
[0fec2b5]: https://github.com/onlyoffice/docspace-mcp/commit/0fec2b53dbb143b801193ac7965253ac91f7d259/
[c0069de]: https://github.com/onlyoffice/docspace-mcp/commit/c0069de16aaab2b0bde2653164563a312d38abb7/
[91e7cd8]: https://github.com/onlyoffice/docspace-mcp/commit/91e7cd84802a15ab53a93e8f611ba8ebbe5b7314/
[2812396]: https://github.com/onlyoffice/docspace-mcp/commit/28123964a9385498f06dd71438cbeab50a285f15/
[c52624d]: https://github.com/onlyoffice/docspace-mcp/commit/c52624d6c125174d27104978bcfbff73e43056f7/
[8ebac70]: https://github.com/onlyoffice/docspace-mcp/commit/8ebac7025ac1de75f1edd78b0c777688105301f6/
[ce1b5b7]: https://github.com/onlyoffice/docspace-mcp/commit/ce1b5b75fe082e4abaf3a74f232ee35463891db0/
[ea5e530]: https://github.com/onlyoffice/docspace-mcp/commit/ea5e5305abc8ca083420fea2014d8f85b0c361ec/
[c443470]: https://github.com/onlyoffice/docspace-mcp/commit/c44347084d3e51e6fd6e174af580085768539f9b/
[8a129ad]: https://github.com/onlyoffice/docspace-mcp/commit/8a129ad28ddd588123af044f74c51f8a7043eb0d/
[3ae9500]: https://github.com/onlyoffice/docspace-mcp/commit/3ae95005e7c0b1a5f40e0401cd6d41ab6939b675/
[c637742]: https://github.com/onlyoffice/docspace-mcp/commit/c63774232644f9479d54768b527f81390959b513/
[90745be]: https://github.com/onlyoffice/docspace-mcp/commit/90745beb9a5827bd8a7a57fc72fe84468403e26b/
[e3e04c7]: https://github.com/onlyoffice/docspace-mcp/commit/e3e04c7435b753a0bfa0b56f3c2b00ffa77e13d3/
