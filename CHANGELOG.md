# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2025-12-29

### Added
- **Recursive Backup:** Support for backing up ABAP packages and their contents recursively.
- **Restore:** Capability to restore objects to an SAP system (upsert mode).
- **Tree Backup:** Option to generate a lightweight tree structure of the package without payloads.
- **Verify:** functionality to verify the backup integrity (source-only).
- **Diff:** Ability to compare backup files with the current system state.
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
- **Authentication:** Integration with `@mcp-abap-adt/auth-broker` for secure connection management.
- **CLI:** Robust command-line interface with logging levels (`-v`, `-vv`, `-vvv`).
