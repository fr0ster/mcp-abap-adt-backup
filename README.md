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

# Lightweight tree without payloads
adt-backup tree --package ZPKG_TEST --output tree.yaml --destination TRIAL

# Restore
adt-backup restore --input backup.yaml --mode upsert --activate --destination TRIAL

# Extract / patch a single object payload
adt-backup extract --input backup.yaml --object class:ZCL_TEST --out ZCL_TEST.abap
adt-backup patch --input backup.yaml --object class:ZCL_TEST --file ZCL_TEST.abap
```

## Logging

Use `-vv` for main stages and `-vvv` for per-object details.

## Roadmap

See `docs/roadmap.yaml` for per-object backup/restore status and the plan for remaining types.
