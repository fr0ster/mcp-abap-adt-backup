# @mcp-abap-adt/adt-backup
[![Stand With Ukraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/badges/StandWithUkraine.svg)](https://stand-with-ukraine.pp.ua)

CLI for recursive ADT backups and restores using `@mcp-abap-adt/adt-clients`.

## Installation

Requires Node.js 22 or 24.

```bash
npm install -g @mcp-abap-adt/adt-backup
```

## Auth Configuration

The CLI uses `@mcp-abap-adt/auth-broker` with stores/providers.

Options:
- `--destination <name>`: destination name for AuthBroker stores
- `--auth-root <path>`: root folder with auth configs (defaults to `AUTH_BROKER_PATH` or cwd)
- `--env <file>`: use a specific `.env` file (via EnvFileSessionStore)
- `--system-type <cloud|onprem|legacy>`: **required for every command that connects.**
  Which kind of system you are dialling; `SAP_SYSTEM_TYPE` in the environment or
  the `.env` file works too. It is not derived from the URL or the authentication
  type — the cloud and on-prem connectors open and release sessions differently,
  and the server cannot be asked which one it is. `legacy` is on-prem below BASIS
  7.50.
- `--browser-auth-port <port>`: callback port for a browser login (default 10001).
  A login opens the system browser and waits up to three minutes.

## Usage

```bash
# Package backup (recursive)
adt-backup backup --package ZPKG_TEST --output backup.yaml --destination TRIAL --system-type cloud

# Plan (offline), then verify it against the target: marks each object create / update / skip
adt-backup plan --input backup.yaml --output plan.yaml
adt-backup verify --plan plan.yaml --destination TRIAL --system-type cloud

# Diff (all objects, or a single --object)
adt-backup diff --input backup.yaml --all --destination TRIAL --system-type cloud

# Restore from the verified plan (new objects and updates activate by default)
adt-backup restore --plan plan.yaml --destination TRIAL --system-type cloud
# --no-activate skips every activation; --transport <request> records the changes

# Extract / patch a single object payload
adt-backup extract --input backup.yaml --object class:ZCL_TEST --out ZCL_TEST.abap
adt-backup patch --input backup.yaml --object class:ZCL_TEST --file ZCL_TEST.abap

# Single object backup (Service Binding)
adt-backup backup --objects serviceBinding:Z_UI_SERVICE --output srvb_backup.yaml --destination TRIAL --system-type cloud
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
| `ddl` | implemented | implemented | source |
| `scalarFunction` | implemented | implemented | source |
| `scalarFunctionImplementation` | implemented | implemented | source |
| `appendStructure` | implemented | implemented | source |
| `functionGroup` | implemented | implemented | metadata-xml |
| `functionModule` | implemented | implemented | source |
| `interface` | implemented | implemented | source |
| `class` | implemented | implemented | source |
| `program` | implemented | implemented | source |
| `transformation` | implemented | implemented | source |
| `serviceDefinition` | implemented | implemented | source |
| `serviceBinding` | implemented | implemented | metadata-xml |
| `metadataExtension` | implemented | implemented | source |
| `behaviorDefinition` | implemented | implemented | source |
| `behaviorImplementation` | implemented | implemented | source |
| `enhancement` | implemented | implemented | source |
| `unitTest` | implemented | implemented | as class |
| `cdsUnitTest` | implemented | implemented | as class |
| `messageClass` | implemented | implemented | json |

> **Note**: Unit tests are stored as classes in backups. When restoring, they are created as test classes in the system.

> **Note**: For `transformation`, the subtype (`SimpleTransformation` for `XSLT/VT` vs `XSLTProgram` for `XSLT/ST`) is detected from the source header (`<?sap.transform simple?>`).

> **Note**: For `serviceBinding`, the publication state (`srvb:published`) is preserved in the backup and re-applied during restore — published bindings are re-published, unpublished bindings are unpublished.

> **Note**: For Message Classes (`MSAG`), the class and its messages are backed up as one atomic JSON unit (parsed, not raw XML). Restore creates the class shell (or, for an existing class, rewrites its description when it differs), upserts each message, and reconciles by deleting target-only messages. Message classes are not activatable and are restored early, with no co-activation.

> **Note**: Documents are restored whole. `domain`, `dataElement`, `tableType` and `functionGroup` are created and then written with the backed-up metadata XML. An existing `package` is left as it is on the target; a missing one is created with the `--super-package` / `--software-component` / `--transport-layer` overrides.

## How restore talks to the system

`@mcp-abap-adt/adt-clients` 23 makes one request per call and composes nothing, so
the sequences are this tool's:

- each object: create → lock → write → unlock → activate, each step judged by an
  `@mcp-abap-adt/adt-strategies` verdict; the unlock runs on every path out of a
  taken lock, and a failure reports SAP's own message;
- group activation starts a run, waits for it (long polling, up to five minutes),
  reads its results, then checks the inactive list;
- the package walk and function-group children are read level by level from the
  repository node structure; a package that does not exist is an error, an empty
  one is an empty tree;
- where-used reads the scope, selects every type and searches with it (without a
  scope resource, it searches unscoped).

A restore that leaves an object failed or inactive prints `Restore incomplete: …`
and exits with status 1.

### Service bindings: what SAP answers, and what restore does with it

A binding is restored as create → **activate** → lock → publish → unlock. Three
of SAP's answers on this path say something other than what they mean:

- **`403` on the LOCK is not a refusal.** It means an editing session holds the
  binding — typically an Eclipse editor someone has open; Eclipse keeps the lock
  after a publication until the editor closes. The publication job does not need
  the lock, and Eclipse itself posts the job after its own LOCK's `403`. Restore
  therefore carries on, prints
  `serviceBinding:<name> is locked by an editor; publishing without the lock`,
  and sends no UNLOCK. Any other `403` — an authorization, say — still stops it.
- **"Service Binding … does not exist" on a publish means "not active".** A
  binding just created has no active version; the publication answers `200` with
  this text. Restore activates the binding first.
- **An unpublish right after a publish is refused** — `200` with *"Error while
  creating service interface <BINDING>_0001_G4BA"*, within a second. The system
  is still finishing the publication; the same request minutes later succeeds.
  Restore reports it as a failure (exit status 1); run it again later.

A publication job takes about two minutes on an idle system and longer on a
loaded one; restore waits up to 15 minutes for its answer.

The measurements behind each point are in adt-clients'
[WORKAROUNDS.md](https://github.com/fr0ster/mcp-abap-adt-clients/blob/main/docs/usage/WORKAROUNDS.md#a-service-binding-is-locked-to-publish-it).

## Upgrading from 2.0.0

- Node.js 22 or 24 is required.
- Pass `--system-type cloud|onprem|legacy` (or set `SAP_SYSTEM_TYPE`) on every
  command that connects; there is no default.
- Backups keep their format. New backups record table types as `xml` (they always
  held the XML); older ones with `source` still restore and diff as documents.
- Message-class payloads no longer carry the raw attribute bag, master system or
  responsible person; comparisons never used them.

## Smoke Checklist

When your landscape is ready, use `docs/SMOKE_CHECKLIST.md` for a focused backup/restore/verify checklist.

## Changelog

See [CHANGELOG.md](./CHANGELOG.md) for a history of changes.

## License

**GNU General Public License v3.0 only** (`GPL-3.0-only`).
Earlier published versions were MIT and stay MIT — a licence change is not
retroactive.

Copyright © 2025–2026 Oleksii Kyslytsia

This program is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation, version 3.

It is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See [`LICENSE`](LICENSE) for the full text.

**What this means.** Running it, and using it on your own data, carries no
conditions at all. Distributing it, or a modified version of it, means passing on
the same freedoms — including the source. This is a finished tool rather than a
library to build on; the libraries it is built from are LGPL, so they can be
linked from programs under any licence.
