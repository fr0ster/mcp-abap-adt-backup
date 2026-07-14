# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

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
