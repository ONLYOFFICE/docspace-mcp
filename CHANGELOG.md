# Changelog

This document records all notable changes to the project, following the [Keep a Changelog] format and adhering to [Semantic Versioning].

## [Unreleased]

<!-- There are no noticeable changes in version [unreleased]. -->

### Added

- Add `fields` filter to `files_get_file_info`, `files_create_folder`, `files_get_folder`, `files_get_folder_info`, `files_get_folders`, `files_rename_folder`, `files_get_my_folder`, `files_create_room`, `files_get_room_info`, `files_update_room`, `files_set_room_security`, `files_get_room_security_info`, `files_get_rooms_folder`, and `people_get_all` tools ([57a5617]).
- Add general filters to `files_set_room_security` and `files_get_room_security_info` tools ([57a5617]).

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

[Unreleased]: https://github.com/onlyoffice/docspace-mcp/compare/v1.1.0...HEAD/
[1.1.0]: https://github.com/onlyoffice/docspace-mcp/compare/v1.0.0...v1.1.0/
[1.0.0]: https://github.com/onlyoffice/docspace-mcp/compare/v0.2.0...v1.0.0/
[0.2.0]: https://github.com/onlyoffice/docspace-mcp/compare/v0.1.3...v0.2.0/
[0.1.3]: https://github.com/onlyoffice/docspace-mcp/compare/v0.1.2...v0.1.3/
[0.1.2]: https://github.com/onlyoffice/docspace-mcp/compare/v0.1.1...v0.1.2/
[0.1.1]: https://github.com/onlyoffice/docspace-mcp/compare/v0.1.0...v0.1.1/
[0.1.0]: https://github.com/onlyoffice/docspace-mcp/releases/tag/v0.1.0/

[57a5617]: https://github.com/onlyoffice/docspace-mcp/commit/57a56174e21dfefd9f0f85e0ef60feb486f69f10/
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
