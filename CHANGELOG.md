# Changelog

All notable changes to this project will be documented in this file.

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