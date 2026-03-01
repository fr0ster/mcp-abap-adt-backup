# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

### Changed

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
