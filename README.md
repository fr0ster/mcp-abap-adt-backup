# @mcp-abap-adt/adt-backup

CLI for recursive ADT backups and restores using `@mcp-abap-adt/adt-clients`.

## Installation

```bash
npm install -g @mcp-abap-adt/adt-backup
```

## Auth Configuration

The CLI uses `@mcp-abap-adt/auth-broker` with stores/providers.

Options:
- `--destination <name>`: destination name for AuthBroker stores
- `--auth-root <path>`: root folder with auth configs (defaults to `AUTH_BROKER_PATH` or cwd)
- `--env <file>`: use a specific `.env` file (via EnvFileSessionStore)

## Usage

```bash
# Package backup (recursive)
adt-backup backup --package ZPKG_TEST --output backup.yaml --destination TRIAL

# Verify (source-only by default)
adt-backup verify --input backup.yaml --destination TRIAL

# Diff (all objects)
adt-backup diff --input backup.yaml --all --destination TRIAL

# Restore (new objects and updates activate by default)
adt-backup restore --input backup.yaml --mode upsert --destination TRIAL
Use `--no-activate-on-create` or `--no-activate-on-update` to skip activation for the respective phases.

# Extract / patch a single object payload
adt-backup extract --input backup.yaml --object class:ZCL_TEST --out ZCL_TEST.abap
adt-backup patch --input backup.yaml --object class:ZCL_TEST --file ZCL_TEST.abap

# Single object backup (Service Binding)
adt-backup backup --objects serviceBinding:Z_UI_SERVICE --output srvb_backup.yaml --destination TRIAL
```

## Help

Get general help or command-specific usage information:

```bash
# General help
adt-backup --help

# Command-specific help
adt-backup restore --help
adt-backup diff --help
```

## Logging

Use `-v` for main stages, `-vv` for per-object details, and `-vvv` for ADT/connection debug logs.

## Roadmap

See `docs/roadmap.yaml` for per-object backup/restore status and the plan for remaining types.

## Supported Object Types

| Object Type | Backup | Restore | Payload |
|---|---|---|---|
| `package` | implemented | implemented | metadata-xml |
| `domain` | implemented | implemented | metadata-xml |
| `dataElement` | implemented | implemented | metadata-xml |
| `structure` | implemented | implemented | source |
| `table` | implemented | implemented | source |
| `tableType` | implemented | implemented | metadata-xml |
| `view` | implemented | implemented | source |
| `functionGroup` | implemented | implemented | metadata-xml |
| `functionModule` | implemented | implemented | source |
| `interface` | implemented | implemented | source |
| `class` | implemented | implemented | source |
| `program` | implemented | implemented | source |
| `serviceDefinition` | implemented | implemented | source |
| `serviceBinding` | implemented | implemented | metadata-xml |
| `metadataExtension` | implemented | implemented | source |
| `behaviorDefinition` | implemented | implemented | source |
| `behaviorImplementation` | implemented | implemented | source |
| `enhancement` | implemented | implemented | source |
| `unitTest` | not-implemented | not-implemented | n/a |
| `cdsUnitTest` | not-implemented | not-implemented | n/a |

## Smoke Checklist

When your landscape is ready, use `docs/SMOKE_CHECKLIST.md` for a focused backup/restore/verify checklist.

## Changelog

See [CHANGELOG.md](./CHANGELOG.md) for a history of changes.
