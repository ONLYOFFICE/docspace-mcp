# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

MCP server for ONLYOFFICE Apps (formerly DocSpace). Package `@onlyoffice/docspace-mcp`. Written in TypeScript that Node runs directly (native type stripping, `.ts` import extensions, no emit step for development). Toolchain versions are pinned in `mise.toml` (Node 24, pnpm 10).

## Commands

```sh
pnpm install --frozen-lockfile
pnpm build-app      # esbuild bundle app/main.ts -> bin/onlyoffice-docspace-mcp.js
pnpm build-mcpb     # MCP bundle (manifest.template.json -> mcpb)
pnpm build-detail   # server.json for the MCP registry (from server.template.json)
pnpm build-docs     # regenerate generated sections of tool docs
pnpm lint-types     # tsc (noEmit)
pnpm lint-code      # eslint
pnpm test           # node --test
node --test test/config.test.ts            # single test file
node --test --test-name-pattern="..." test/config.test.ts
pnpm serve          # run app/main.ts with .env loaded
pnpm inspect        # run under @modelcontextprotocol/inspector with DOCSPACE_* env forwarded
```

- Tests spawn the **bundled** `./bin/onlyoffice-docspace-mcp.js`, so run `pnpm build-app` before `pnpm test` (and `build-mcpb`/`build-detail` for `mcpb.test.ts`/`detail.test.ts`). CI (`.github/workflows/audit.yml`) runs: build-app, build-mcpb, build-detail, lint-types, lint-code, test.
- `scripts/env.ts` loads `.env` from the repo root for `serve`/`inspect`.
- `scripts/build-docs.ts` still targets `docs/features/tools.md` and `docs/installation/local-server.md`, which no longer exist (docs moved to `docs/reference/`, `docs/getting-started/`).

## Architecture

**Entry point** `app/main.ts` does all wiring by hand (no DI framework). It parses env via `config.EnvSchema`, then either:
- `startStdio` — a single MCP protocol with credentials from env. If config parsing fails, the server still starts on stdio with `mcp.ErroredServer`, which reports the config error to the client instead of crashing (logger is muted on stdio).
- `startHttp` — an Express app hosting SSE (`/sse`), Streamable HTTP (`/mcp`), and optionally OAuth routes. `DOCSPACE_TRANSPORT=http` enables both SSE and Streamable. A **new MCP protocol + API client is created per session** in `create(req)`, using auth resolved from the request (`req[auth.authKey]` / `req[oauth.oauthKey]`) and per-request settings (toolsets, tools, dynamic) parsed from query/headers by `config.SettingsParser`.

**Modules under `lib/`** — each directory has a barrel file (`lib/<name>.ts`) that re-exports; import through the barrel (`import * as mcp from "../lib/mcp.ts"`).
- `api/core` — typed ONLYOFFICE Apps REST client (`Client` with `files`, `people`, `auth` services) and zod schemas for DTOs. Auth is layered via immutable `withAuth`/`withApiKey`/`withAuthToken`/`withBasicAuth`/`withBearerAuth`.
- `api/extra` — higher-level helpers: `Resolver` (waits for long-running file operations), `Uploader`, and `FileOperationPoller`/`FileOperationCaller` communicating over an `EventEmitter` bus.
- `mcp/server.ts` — **all tool definitions and handlers**. Tools are grouped in `regularToolsets` (zod input/output schemas converted to JSON Schema, plus annotations) and dispatched through `callRegularToolHandlers`. With `dynamic` (meta tools) enabled, only `metaTools` (`list_toolsets`, `list_tools`, `get_tool_input_schema`, `call_tool`, …) are exposed and they proxy to regular tools. Adding a tool = schema + entry in `regularToolsets` + handler in `callRegularToolHandlers`; `lib/config/tools.ts` derives available tool/toolset names from `regularToolsets`.
- `mcp/sessions.ts`, `sse-*`, `streamable-*` — HTTP transports and session TTL management.
- `auth` — `AuthManager` Express handler resolving credentials from defaults, headers/query (`CredentialParser`), internal headers (`InternalCredentialParser` when `DOCSPACE_INTERNAL`), or OAuth.
- `oauth` — an OAuth 2.0 authorization server proxy in front of ONLYOFFICE Apps (metadata endpoints, dynamic client registration, authorize/callback/token/introspect/revoke), issuing its own JWTs (`AuthTokens`, `StateTokens`).
- `config` — `spec.ts` is the **single source of truth for every option** (env name, query/header name, type, default, which distributions/transports it applies to). `env.ts` builds the zod env schema (prefix `DOCSPACE_`), `settings.ts` parses per-request settings. `build-detail`/`build-mcpb` generate distribution metadata from `spec.ts`, and `test/config.test.ts` asserts env schema and spec stay in sync — a new option must be added to both.
- `util/*` — cross-cutting infrastructure: custom MCP `Protocol`/router layer (`util/mcp`), plus context propagation via fetch/express wrappers for abort signals, trace IDs, and forwarded headers (`util/abort`, `util/trace`, `util/forwarded`), logfmt logger, rate limiting, CORS, hostname allow-listing.

## Conventions

- Error handling uses the `Result` type from `lib/util/result.ts` (`r.ok(v)`, `r.error(err)`, check `.err` before reading `.v`; `r.safeNew`, `r.safeAsync` wrap throwing code) rather than exceptions. Errors are wrapped with `new Error("Doing X", {cause})`.
- Style is enforced by `eslint.config.js` (`@eslint/js` + `typescript-eslint` `recommendedTypeChecked` + `@stylistic` + a few `import-x` rules; only `.js`/`.ts` files are linted; `no-unsafe-*` rules are off until untyped JWT payloads, request bodies and query values are typed): two-space indentation, no semicolons, double quotes, `let` over `const` for locals, short local variable names, `async()` without space.
- Record notable changes in `CHANGELOG.md` under `[Unreleased]` (Keep a Changelog format, with commit-hash link references at the bottom).
