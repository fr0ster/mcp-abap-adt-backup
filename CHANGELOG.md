# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [3.0.2] - 2026-09-27

### Changed

- **Node.js 26 is supported**: `engines` is `"^22 || ^24 || ^26"`. Under Node 26 npm skipped every release whose `engines` did not admit it and installed the newest one that did — silently an older major, for this package one without the restriction. Measured: `npm i -g @mcp-abap-adt/proxy` on Node 26.7.0 installed 4.2.0 while 5.0.1 was `latest`.

## [3.0.1] - 2026-09-27

### Fixed

- **Deleting a package that held a published service binding refused
  everything.** A package walk also lists what the system generated for the
  binding — `G4BA`, `SCO2`, `SUSH` — and those have no ADT address: the
  deletion check answered "No URI-Mapping defined for URI" inside its `200`,
  and the whole group was refused, so nothing was deleted. Restore's deletion
  (`deleteBackupObjects`) and `scripts/delete-package.ts` now take only what
  this tool restores; the generated objects go with their binding. Measured on
  a cloud system: with them the check refused the group; without them the 26
  objects of a test package were checked and deleted, and the generated ones
  were gone with the binding. The script also builds its references through
  `objectReference`, as restore does.

## [3.0.0] - 2026-09-27

Moves to `@mcp-abap-adt/adt-clients` 23, which makes one request per call and
composes nothing: the sequences are this tool's now. **Breaking**: Node.js 22 or
24, and `--system-type` on every command that connects — see *Upgrading* in the
README. On npm this follows 1.7.0; 2.0.0 (the licence change) was released on
GitHub only.

### BREAKING

- **Node.js 22 or 24** (`engines.node: ^22 || ^24`), as `@mcp-abap-adt/auth-broker` 3 requires.
- **Every command that connects needs `--system-type cloud|onprem|legacy`** (or `SAP_SYSTEM_TYPE` in the environment or the `--env` file). The connector is chosen from it — `AdtCloudConnector` or `AdtOnPremConnector` (`legacy`: on-prem below BASIS 7.50) — and never inferred from the URL or the authentication type. Without it the command stops before connecting and says so.

### Changed

- Dependencies: `@mcp-abap-adt/adt-clients` `^7.3.1` → `^23.0.2`, new `@mcp-abap-adt/adt-strategies` `^0.6.0`, `@mcp-abap-adt/connection` `^1.8.0` → `^9.4.0`, `@mcp-abap-adt/auth-broker` `^1.0.5` → `^3.0.1`, `@mcp-abap-adt/auth-providers` `^1.0.5` → `^4.2.0`, `@mcp-abap-adt/auth-stores` `^1.0.4` → `^1.2.4`. The two lower bounds go together: from connection 9.3.1 only stateful requests carry the ABAP context, and before adt-clients 23.0.2 the UNLOCK of an include, a service binding or a message class went out stateless and released nothing. auth-stores 1.2.4 reports a session file it cannot read instead of answering it as no session. The deleted `@mcp-abap-adt/interfaces` facade is gone; contract types come from `@mcp-abap-adt/interfaces-adt` `^11`, `interfaces-adt-connection` `^1`, `interfaces-auth` `^2.1`, `interfaces-auth-sap` `^1.0.1`, `interfaces-utils` `^1.1`.
- The session is opened with `connect()` before the first request and given back with `disconnect()` when the command ends, success or not.
- Browser login goes through `browserCallbackStrategy` on the same callback port as before (`--browser-auth-port`, default 10001) and waits up to three minutes; a login that does not complete is reported as such. A token is renewed through the broker only where UAA credentials stand behind it.
- adt-clients 23 makes one request per call and composes nothing, so the sequences are this tool's now:
  - **restore** writes every object with one sequence — create → lock → write → unlock → activate — replacing two near-identical per-type chains. Each step is judged by an adt-strategies verdict; the unlock runs on every path out of a taken lock; a failure carries SAP's message.
  - **documents are written whole**: domains, data elements, table types and function groups are created and then written with the backed-up metadata XML (`updateMetadata`), instead of a document the library assembled from a few fields.
  - **group activation waits for its run** (long polling, up to five minutes), reads the results with `analyseActivation` and prints SAP's messages; the inactive list is still what the per-object report states. The fixed 5 × 10 s poll is gone.
  - **the package walk and function-group children** are read by the tool (ported from adt-clients' `scripts/lib`). An empty package is an empty tree; a package that does not exist is an error (it is asked of `/packages/{name}` first).
  - **where-used** reads the scope, selects every type and searches with it; without a scope resource (404) it searches unscoped. Interfaces are asked about as `INTF/OI`, structures as `TABL/DS`, behavior implementations as `CLAS/OC`; message classes are no longer asked about.
  - **group deletion** is judged by `analyseDeletion`, so a refusal SAP writes inside a `200` stops it.
- Reads: a `404`/`410`, or a `200` with an empty body, is "nothing to take" (ADT answers both for a missing object and for an empty one); any other failure is an error with SAP's message. Text matches such as "not found" inside another status no longer count as absence.
- Table types are backed up as `xml` (they always held the XML); older backups with `source` still restore and diff as documents.
- Message classes are parsed by the tool from the raw class document; the payload keeps name, description, package, languages and messages. An existing class's description is rewritten only when it differs (read, edit, lock, write, unlock).
- An existing package is no longer rewritten on restore: its document carries the source system's software component and transport layer.
- A `403` during restore is still skipped, and the skip line now carries SAP's text (authorization or a lock held elsewhere).

### Fixed

- The behavior-definition name was never read from a behavior implementation's source (double-escaped regex); a behavior implementation could not be created from a backup whose config lacked it.
- **Group activation left whole groups inactive when they held a function include or module.** The activation reference carried no function group, adt-clients refuses such a reference before sending anything, and the run for the whole group never started. Activation now builds its references the way deletion already did (`objectReference`): a `FUGR/I` or `FUGR/FF` carries its group as `parentName`. Measured on a cloud trial package of 26 objects: 19 stayed inactive before, 3 after (the three the system itself cannot activate).
- **`--env <file>` ignored the file.** The CLI took the path only from `--env-path` and treated `--env` as a flag, so the documented form looked for `SAP_URL` in the process environment and stopped with "Missing connection config for destination env". `--env <file>` now reads the file; a bare `--env` still reads the environment.
- **A restored service binding could not be published.** It was created and published in one step, and the publication answered `200` with "Local Publish of <binding> failed — Service Binding … does not exist": a binding just created has no active version. It is now activated first, then published under its lock (as Eclipse does), with the lock released whatever the job answers. The service's information read (`generateServiceBinding`, a GET) is not the missing step — measured: after the GET the publication still failed, after the activation it succeeded (134 s).
- **The publication timed out before it finished.** It ran on the library's 120 s default while the job takes 133 s on an idle system and minutes on a loaded one. It now waits up to 15 minutes for the job's own answer; nothing polls.
- **A binding an editing session holds is published without our lock.** Its LOCK answers `403` — an open Eclipse editor keeps the lock after a publication — and the publication does not need ours; Eclipse itself posts the job after its own LOCK's `403`. The LOCK is read by `analysePublicationLock` (adt-strategies 0.6.0): a `403` answers a lock without a handle, restore publishes, logs that it did so without the lock, and sends no UNLOCK. A refusal other than `403` still stops it.
- **A failed unlock after a binding's publication went unreported.** The answer of the unlock was never read, so a restore reported success while the lock could still be held. It is now judged as the write sequence judges it: after a publication that succeeded, a failed unlock is the failure; when the publication failed — refused, or an exception thrown on the way — that error is the one reported and a failed unlock is logged beside it. The unlock runs in every case.
- **A restore with failures exited 0 and could say "All objects are active".** The failed object was never activated and never counted, so the final line spoke only for the others. The final line now says when failed objects were not processed, a restore that leaves failures or inactive objects ends with `Restore incomplete: …` and exit status 1.
- **`diff` and `verify` compared a document-backed object by its package alone.** A domain, data element, function group or table type whose definition changed — a new row type, other keys, another value table — reported "No differences" and `ok`. Both now compare the definition (`canonicalDocument`: the document without what a save rewrites — change and creation stamps, version slot, responsible person, master system, etags, navigation links). For a table type this is a regression from the previous release, which compared it as text.
- **`backup --objects tableType:…` kept only the name and package.** A table type has no source, and the flat backup fell through to the source read. It now keeps the document whole.
- **`diff` ignored `--objects` backups.** A flat backup (schema 1) fell through and printed nothing, which read as "no differences" — the documentation promised `diff` for exactly these. It now compares each object that carries content and says which ones it cannot (`--show-ok`).
- **`extract` read only package backups.** An `--objects` backup (schema 1) holds a flat list with the source as is, and `extract` looked for a tree in it and crashed on `undefined`. It now reads both.

### Removed

- The flat (`schemaVersion 1`) restore path (`restoreObject`, `restoreObjects`, `sortByDependencies`), which no command used. `backup --objects` still writes such backups for `diff`/`check`.
- Debug scripts built on removed library calls: `scripts/test-hierarchy.ts`, `debug-where-used-list.ts` (and the `debug:deps` npm script), `dump-adt-xml.js`, `debug-nodestructure.ts`, `test-obj-structure.ts`, `test-virtual-folders.ts`. `scripts/delete-package.ts` is rewritten on the new calls and takes the system type as its fourth argument.

### Documentation

- README: a restore left incomplete exits with status 1; SAP's answers that mean
  something other than what they say (a `403` on a service binding's LOCK among
  them) are pointed to adt-clients' SAP ADT errata (its object tree) rather than
  repeated here.
- `README.md` and `docs/SMOKE_CHECKLIST.md` showed `verify --input` and `restore --input --mode upsert --force`, which the CLI no longer takes. They now show `plan` → `verify --plan` → `restore --plan`, give every online command its `--system-type`, and compare an `--objects` backup with `diff`, since only a package backup can be planned.

### Tests

- `scripts/integration-test.mjs` follows the current CLI: `backup` → `validate` → `plan` → `verify --plan` → `restore --plan`. It called `list` (removed in February), `verify --input`/`--strict` and `restore --input`/`--force`, none of which exist any more. `tests.verify.strict` and `tests.restore.force` are gone from the template.
- `npm run test:offline` runs `tests/offline/messageclass.cjs` and the new `tests/offline/sequences.cjs`; the fakes answer `IAdtResponse` as adt-clients 23 does.

## [2.0.0] - 2026-09-03

### Licence

- **This tool is now `GPL-3.0-only`.** It was MIT up to and including 1.7.0, and
  those versions stay MIT — a licence change is not retroactive.

  A finished tool rather than a library to build on, so it takes the full GPL
  rather than the LGPL its own dependencies carry: running it and using it on your
  own data carries no conditions, while distributing it — or a modified version —
  means passing on the same freedoms, source included.

  Copyright © 2025–2026 Oleksii Kyslytsia.


## [1.7.0] - 2026-07-14

### Added
- Message class (`MSAG`) backup/restore/verify/diff support. Class and its messages are one atomic backup unit (JSON payload); restore creates the shell, upserts messages, and reconciles (deletes target-only messages). Not activatable; restored early with no co-activation.
  - Some systems (e.g. BTP ABAP trial) register a newly created message class asynchronously, so its messages are not immediately editable (`LOCK_MSG` → 403 EU510) for a few minutes. Restore retries the message upsert with backoff to give the system time; if the object is still not editable when the window is exhausted, the shell remains and re-running restore later (idempotent) populates the messages.

### Changed
- Bump `@mcp-abap-adt/adt-clients` to `^7.3.1` (adds message-class module).

### Fixed
- `diff --all` now actually compares every object in a schemaVersion-2 (tree/package) backup by walking the tree nodes; previously it returned without diffing anything.
- `diff` honors `--show-ok`: unchanged objects print `No differences` only when `--show-ok` is set, keeping large `--all` runs readable.

## [1.6.2] - 2026-07-01

### Security
- Resolved all open Dependabot alerts (18 total: 11 high / 6 medium / 1 low, all transitive). `npm audit`: 0 vulnerabilities.
- `@mcp-abap-adt/adt-clients` `^6.0.0` → `^7.2.1` — pulls **axios 1.18.1** (was 1.15.1), fixing axios ReDoS / proxy-auth leak / prototype-pollution (MitM), plus `follow-redirects` and `form-data`. No API changes affect this project.
- Updated `@mcp-abap-adt/auth-broker` (esbuild), `@mcp-abap-adt/auth-providers` (express → qs / path-to-regexp), `@mcp-abap-adt/connection`, and `fast-xml-parser` (fast-xml-builder); pinned patched transitives via lockfile (`form-data` 4.0.6, `path-to-regexp` 8.4.2, `qs` 6.15.3).

## [1.6.1] - 2026-06-28

### Changed
- CI and release workflows build on **Node 22** (dropped Node 20); bumped GitHub Actions (`actions/checkout@v5`, `actions/setup-node@v5`, `softprops/action-gh-release@v2`), clearing the Node 20 runtime deprecation warning.
- `engines.node` raised to `>=22.0.0`.

## [1.6.0] - 2026-06-28

### Added
- **New object type `scalarFunction`** (`DSFD/SCF`, payload source): backup and restore of CDS scalar function definitions.
- **New object type `scalarFunctionImplementation`** (`DSFI/SFI`, payload source): backup and restore of CDS scalar function implementations; config captures `scalarFunctionName` and `engineValue`.
- **New object type `appendStructure`** (`TABL/DS`, payload source): backup and restore of ABAP append structures; config captures `baseObject`.
- **AMDP co-activation group**: dependency analysis now emits a single `isCircular: true` group containing the AMDP class, its table-function DDL, and the associated scalar function definition + implementation, ensuring they are bulk-activated together during restore.

### Changed
- **`view` → `ddl`**: internal `SupportedType` value and ADT type mapping (`DDLS/…`) renamed from `view` to `ddl` to reflect that the type covers all CDS DDL sources (views, table functions, abstract entities), matching `adt-clients` 6.0.0.
- `@mcp-abap-adt/adt-clients` `^5.x` → `^6.0.0` (renames internal type `view` → `ddl`).

## [1.5.0] - 2026-06-19

### Added
- **Restore of function-group includes.** `functionInclude` is now restore-implemented (it was `restoreStatus: not-implemented` in 1.4.0): the TOP include (`L<FUGR>TOP`, auto-created with the function group) is restored by updating its source only; custom includes are created and then sourced. Wired through `restoreObject` / `restoreTreeNode` (TOP-vs-custom branch), `verify` (`readMetadataXmlForType` reads include metadata via `getFunctionInclude().readMetadata()`), dependency ordering (`functionInclude` after `functionGroup`, before `functionModule`), and the `GROUP|NAME` object-spec helpers (`getNodeObjectSpec`, `objectId`, `formatObjectSpec`, `parseObjectSpec`, `applyConfigName`, `normalizeType`, `typeOrder`, `analyzeDependencies`). The underlying `getFunctionInclude().create()/update()/activate()` primitives are verified on a real system.

## [1.4.0] - 2026-06-17

### Added
- **Function group children in package backups.** When backing up a package, each function group now captures its **function modules** (`FUGR/FF`) and **includes** (`FUGR/I` — TOP global data + custom includes) as children, with their source. These are not exposed by the package hierarchy; they are enumerated via `getUtils().listFunctionModules()` / `listFunctionGroupIncludes()`. The generated `L<FUGR>UXX` collector is skipped (no developer content; regenerated on restore). Function modules restore as before (`ok`); includes are captured with `restoreStatus: not-implemented` for now (restore is feasible via `getFunctionInclude().create()` and a follow-up).
- New `SupportedType` value `functionInclude` (`FUGR/I` mapping; source read via `getFunctionInclude().read()`).

### Changed
- `@mcp-abap-adt/adt-clients` `^5.4.1` → `^5.8.0` (adds `listFunctionModules`/`listFunctionGroupIncludes`; `getFunctionInclude().read()` now returns source; `delete()` surfaces server-refused deletions).

## [1.3.0] - 2026-04-20

### Added
- **Transformation support:** New object type `transformation` covering both `XSLT/VT` (SimpleTransformation) and `XSLT/ST` (XSLTProgram). Backup, restore, verify, and dependency analysis all handle the new type. Subtype is detected from the source header (`<?sap.transform simple?>` => SimpleTransformation, otherwise XSLTProgram).
- **Service binding publication state:** `parseServiceBindingConfig` now reads the `srvb:published` attribute and sets `desiredPublicationState` accordingly, so restore re-publishes/unpublishes bindings to match the source system.
- New helper `utils/detectTransformationType.ts`.

### Changed
- **Dependency upgrades:**
  - `@mcp-abap-adt/adt-clients` `^2.2.0` → `^5.4.1` (major). The new `IServiceBindingConfig` exposes a single `bindingVariant` field (`ODATA_V2_UI` / `ODATA_V2_WEB_API` / `ODATA_V4_UI` / `ODATA_V4_WEB_API`) instead of separate `bindingType`/`bindingVersion`/`bindingCategory`; `parseServiceBindingConfig` now derives `bindingVariant` from XML.
  - `@mcp-abap-adt/auth-stores` `^1.0.2` → `^1.0.4`
  - `@mcp-abap-adt/connection` `^1.1.0` → `^1.8.0`
  - `fast-xml-parser` `^5.4.1` → `^5.7.1`
  - `yaml` `^2.8.2` → `^2.8.3`
  - `@biomejs/biome` `^2.4.4` → `^2.4.12`
  - `@types/node` `^25.3.1` → `^25.6.0`
  - `typescript` `^5.9.2` → `^6.0.3` (major)
- **Engines:** `node >=18.0.0` → `node >=20.0.0` (Node 18 reached EOL).
- **TypeScript config:** added `types: ["node"]` (TS 6 no longer auto-includes `@types/node`) and `ignoreDeprecations: "6.0"` for `moduleResolution: node`.

## [1.2.0] - 2026-03-04

### Changed
- **Plan grouping:** Replaced type-phase (PLAN_PHASES) plan generation with SCC-based dependency level analysis. Objects are grouped by dependency level (`level = max(dependency level) + 1`), with independent SCCs at the same level merged into a single group.
- **Plan-driven restore:** Restore now follows the plan's group order directly. Each group's objects are created inactive then bulk-activated together. Falls back to type-phase restore when no plan is provided.
- **Intra-group creation order:** `TYPE_CREATION_ORDER` ensures correct creation order within groups (e.g. BDEF before BIML class), preventing SAP errors when objects depend on each other within a circular group.
- **Activation diagnostics:** Activation now parses XML response messages from SAP for error reporting and skips polling when errors are detected.
- **Activate command:** Checks actual inactive state before activating; reports per-object status after activation.
- **Dependency analysis refactor:** Extracted `buildAdjacency`, `tarjanSCC`, `buildSccDag` as shared helpers. Added `analyzeDependencyLevels` function.

### Fixed
- **Verify false positives:** `readMetadataXmlForType` now correctly returns `null` (not found) when ADT clients swallow HTTP 404 and return `undefined`. Previously reported UPDATE for objects that don't exist in the target system.

## [1.1.0] - 2026-03-01

### Changed
- **Dependencies:** Upgraded `@mcp-abap-adt/adt-clients` from ^1.1.1 to ^2.2.0.
- **System context:** `AdtClient` now receives `masterSystem` and `responsible` via constructor options. On cloud (BTP) systems both values are resolved from the ADT system-information endpoint; on on-premise systems `responsible` is taken from the connection username.

## [1.0.0] - 2026-02-27

### Added
- **Multi-step restore workflow:** New `tree`, `enrich`, `plan`, `verify`, `check`, and `activate` commands enabling a staged backup-to-restore pipeline (`backup` → `plan` → `verify` → `restore`).
- **Object Support:** Added `accessControl` (DCLS/DL) support across backup/restore/verify flows.
- **Granular restore phases:** 17 per-type phases with dedicated activation strategies:
    - **Individual** (activate on create/update): domains, data elements, structures, tables, table types, classes, interfaces, programs, function groups, function modules, enhancements.
    - **Bulk** (collect + single activation): behavior definitions + implementations, access controls, metadata extensions, service definitions, service bindings.
    - **Cluster** (SCC-based dependency grouping): CDS views — interdependent views activate together per cluster.
- **Final activation sweep:** Safety-net bulk activation of all processed objects after all phases complete.
- **Dependency analysis:** Tarjan's SCC algorithm for cycle detection and topological ordering of restore groups.
- **BDEF source parser** (`parseBdefSource`): Extracts `rootEntity` and `implementationType` from behavior definition source code for config enrichment.
- **Post-restore verification:** Automatic verification after restore to confirm object activation status.
- **CLI options:** `--target` (alias for `--destination`), `--env-path` (alias for `--env`), `--skip-existing`, `--skip-unchanged`, `--super-package`, `--transport-layer`, `--no-activate`, `--browser-auth-port`, `--mcp`.
- **Verbosity levels:** `-v` (progress), `-vv` (per-object details), `-vvv` (ADT debug).

### Changed
- **Restore strategy:** Replaced broad phase groups (Foundation, Implementation, etc.) with granular per-type phases, each with its own activation strategy.
- **Package restore:** Added 2s delay after creation for SAP DB commit; always removes `responsible` field; requires explicit `superPackage` or `--super-package` override.
- **Domain/data element/function group restore:** Always update after create to set full definition (create only registers the name).
- **Service binding restore:** Fallback to create+update if update returns 404 despite verify passing.
- **Verify:** Now supports `pre-restore` and `post-restore` modes with progress logging.
- **Dependencies:** Upgraded `@mcp-abap-adt/adt-clients` to ^1.1.1, `fast-xml-parser` to ^5.4.1.

### Breaking Changes
- **Restore workflow is now multi-step.** Direct `restore --input backup.yaml` no longer works. Use `plan` → `verify` → `restore` pipeline.
- **`@mcp-abap-adt/adt-clients` ^1.1.0** required (API changes for access control support).
- **Root packages must have `superPackage`** specified in backup or via `--super-package` CLI flag.

## [0.1.2] - 2026-02-21

### Added
- **Object Support:** Added `serviceBinding` support across backup/restore/verify flows.
- **Documentation:** Added smoke test checklist for landscape validation in `docs/SMOKE_CHECKLIST.md`.

### Changed
- **Type Mapping:** Extended ADT type mapping and object normalization for `SRVB/SVB` / `serviceBinding`.
- **Roadmap:** Marked `serviceBinding` as implemented for backup and restore in `docs/roadmap.yaml`.

## [0.1.1] - 2025-12-31

### Changed
- **Maintenance:** Removed unused utility functions and files to reduce codebase size.
- **Code Quality:** Fixed various linting issues, unused variables, and type safety warnings.

## [0.1.0] - 2025-12-31

### Added
- **Recursive Backup:** Support for backing up ABAP packages and their contents recursively.
- **Restore:** Capability to restore objects to an SAP system (upsert mode).
- **Restore Enhancements:** Support for Software Component override (`--software-component`) and inheritance during restore.
- **Verify:** Functionality to verify the backup integrity (source-only).
- **Diff:** Ability to compare backup files with the current system state.
- **Strict Checks:** Pre-deletion validation (`delete-package` script) and strict restore checks to prevent accidental data loss.
- **Object Support:**
    - Fully implemented Backup & Restore:
        - Package
        - Domain
        - Data Element
        - Structure
        - Table
        - View
        - Function Group
        - Function Module
        - Interface
        - Class
        - Program
        - Service Definition
        - Metadata Extension
        - Behavior Definition
- **Authentication:** Integration with `@mcp-abap-adt/auth-broker` for secure connection management.
- **CLI:** Robust command-line interface with logging levels (`-v`, `-vv`, `-vvv`) and command-specific help (e.g., `adt-backup restore --help`).

### Changed
- **Dependencies:** Improved dependency collection and handling using native ADT "Where-Used" list.
- **Backup:** Unified backup command; removed separate `tree` command (metadata is always included in backups).
