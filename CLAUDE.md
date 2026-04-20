# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CLI tool for recursive backup and restore of SAP ABAP objects using the ADT (ABAP Development Tools) protocol. Part of the `@mcp-abap-adt` monorepo ecosystem.

## Build & Development Commands

```bash
# Build (clean + lint + compile)
npm run build

# Fast build (TypeScript only, no lint)
npm run build:fast

# Lint and auto-fix
npm run lint

# Lint check only
npm run lint:check

# Format code
npm run format

# Run integration tests (requires SAP connection)
npm run test:integration
```

No automated test framework is configured. For validation, build and exercise the CLI manually (see `docs/SMOKE_CHECKLIST.md`).

## Architecture

### Entry Point

- `src/bin/adt-backup.ts` → `src/lib/run.ts` — Main command dispatcher; all CLI commands are handled as `if (command === '...')` blocks in `run()`.

### Multi-Step Restore Workflow

The full backup→restore pipeline is a multi-step process (each step produces a YAML file consumed by the next):

1. **`backup --package`** — Recursively walks package hierarchy via ADT, fetches source/metadata for all objects, writes a `BackupTreeFile` (schemaVersion 2)
2. **`plan`** — Offline step: analyzes dependencies via `analyzeDependencies()`, produces a `RestorePlan` with ordered groups
3. **`verify`** — Online step: checks each plan action against the target system, updates actions to `create` or `update`
4. **`restore`** — Online step: executes the plan in two phases (packages first, then dependency groups with bulk activation), runs post-restore verification

Alternative lighter workflows exist: `tree` → `enrich` (two-step backup), `check` (verify without a plan), `backup --objects` (flat schemaVersion 1 backup of individual objects).

### Restore Strategy (restoreTreeBackup.ts)

Restore uses a two-phase approach:
- **Phase 1**: Restore package hierarchy recursively (parent before child)
- **Phase 2**: Restore non-package objects in dependency groups via `analyzeDependencies()`. Each group's objects are created/updated as inactive, then bulk-activated together. Circular dependency groups are handled as a single activation unit.

### Backup Schema Versions

- **SchemaVersion 1** (`BackupFile`) — Flat list of `BackupObject[]`, used by `--objects` backup
- **SchemaVersion 2** (`BackupTreeFile`) — Hierarchical tree of `BackupTreeNode`, used by `--package` backup. Each node may have `children`, `codeBase64`, `config`, `codeFormat`

### Object Payload Formats

Objects store their payload in one of two formats (see `docs/roadmap.yaml` for which):
- **`source`** — ABAP source code (classes, programs, views, structures, tables, etc.)
- **`metadata-xml`** — ADT XML metadata (packages, domains, data elements, function groups, service bindings, table types)

The format is tracked per node in `codeFormat` and determines how backup/restore/diff operations handle the content.

### ADT Type Mapping

`mapAdtTypeToSupported.ts` converts ADT type strings (e.g., `CLAS/OC`, `TABL/DT`, `FUGR/FF`) to internal `SupportedType` values. This mapping is central to how the tool discovers and categorizes objects from the SAP system.

### Core Modules (`src/lib/`)

- **auth/** — Authentication via `@mcp-abap-adt/auth-broker`. Supports `--destination` (named system), `--env`/`--env-path` (.env file)
- **backup/** — Fetch source code (`readSourceText`) and metadata XML (`readMetadataXmlForType`) from ADT
- **restore/** — `restoreTreeBackup` (full pipeline), `restoreObject` (per-type logic), `analyzeDependencies` (SCC-based grouping), `sortByDependencies`/`sortTreeNodesByDependencies`
- **tree/** — `buildPackageBackupTree` (recursive tree construction), `enrichTreeNode` (add payload/config), `mapAdtTypeToSupported`, `flattenTree`, `findNodeInTree`
- **verify/** — `verifyBackup` (compare backup vs system), `verifyObjectInSystem` (single object check). Supports `pre-restore` and `post-restore` modes
- **dependencies/** — `collectTreeDependencies` (fetch where-used lists from ADT)
- **xml/** — XML parsing with `fast-xml-parser`. Type-specific parsers (`parseClassConfig`, `parseDomainConfig`, etc.) and utilities (`extractMetadata`, `findNode`)
- **crypto/** — Checksums for backup integrity: file-level (`computeBackupChecksum`) and tree-level (`updateTreeChecksums`/`verifyTreeChecksums`)
- **cli/** — Argument parsing (`parseArgs`), usage text, verbosity control (`-v`/`-vv`/`-vvv`), log environment
- **utils/** — `parseObjectSpec`/`formatObjectSpec` (parse `type:name` strings), `diffUnified`
- **state/** — Global verbosity state

### Key Types (`src/lib/types.ts`)

- `SupportedType` — Union of ~22 supported ABAP object types (incl. `transformation` for XSLT/ST and SimpleTransformation)
- `BackupFile` / `BackupTreeFile` — The two backup formats
- `BackupTreeNode` — Tree node with optional `codeBase64`, `config`, `children`, `codeFormat`, `usedBy`
- `RestorePlan` / `RestorePlanGroup` / `RestorePlanAction` — Restore execution plan
- `ObjectSpec` — `{ type, name, functionGroupName? }` used throughout for object identification

## CLI Commands

- `backup` — Create backup (package tree or individual objects)
- `tree` — Fetch package hierarchy and dependencies (no source)
- `enrich` — Populate tree file with metadata and source
- `plan` — Build dependency-based restoration sequence (offline)
- `verify` — Update plan with target system state (online)
- `check` — Compare backup against target system (online)
- `restore` — Execute restoration plan on target system (online)
- `diff` — Show differences between backup and system
- `validate` — Verify backup file integrity (checksums, offline)
- `list` — List objects in backup file
- `extract` — Extract single object payload to file
- `patch` — Update object payload in backup file

## Code Style & Language

- All code artifacts (code, comments, commit messages, PR descriptions) must be in English
- Respond to the user in the language they use to communicate
- Biome for linting/formatting (2-space indent, single quotes, semicolons)
- TypeScript strict mode, target es2022, CommonJS output
- `noExplicitAny`: warn in production, off in tests
- Biome also handles import organization (`organizeImports: on`)

## Commit Convention

Short imperative summaries, <= 72 chars. Use scope when useful (e.g., `cli: handle empty backup files`).

## Key Dependencies

- `@mcp-abap-adt/adt-clients` — ADT API client (core SAP interaction)
- `@mcp-abap-adt/connection` — ABAP connection handling
- `@mcp-abap-adt/auth-broker` / `auth-providers` / `auth-stores` — Authentication ecosystem
- `fast-xml-parser` — XML parsing for ADT responses
- `yaml` — YAML serialization for backup files

## Plans and Specs

Plans under `docs/superpowers/plans/` and specs under `docs/superpowers/specs/` are kept in the tree only while active — i.e. not yet implemented and not cancelled. Once a plan/spec has been fully implemented OR cancelled, delete the file. History lives in git; these directories hold only work in progress.
