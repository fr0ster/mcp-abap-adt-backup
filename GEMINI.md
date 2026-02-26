# Project Context: @mcp-abap-adt/adt-backup

## Overview
`@mcp-abap-adt/adt-backup` is a CLI tool for performing recursive backups and restores of SAP ABAP objects using the ADT (ABAP Development Tools) interfaces. It interacts with SAP systems to serialize packages and their contents into YAML/XML formats and can restore them back to a system.

## Tech Stack
- **Language:** TypeScript (Node.js >= 18)
- **Build System:** `tsc` (TypeScript Compiler)
- **Linting/Formatting:** Biome (`biome.json`)
- **Dependencies:**
    - `@mcp-abap-adt/*`: Core libraries for ADT communication and authentication (adt-clients, auth-broker, auth-providers, auth-stores, connection).
    - `fast-xml-parser`: XML processing.
    - `yaml`: YAML processing.

## Project Structure
- **`src/bin/adt-backup.ts`**: Entry point for the CLI.
- **`src/lib/`**: Core logic.
    - **`run.ts`**: Main execution flow.
    - **`auth/`**: Authentication handling (providers, stores).
    - **`backup/`**: Logic for backing up objects (reading metadata/source).
    - **`restore/`**: Logic for restoring objects (creation, activation).
    - **`tree/`**: Tree construction and manipulation (dependency handling).
    - **`verify/`**: Comparison of local backups with system state.
    - **`crypto/`**: Checksum calculation and verification (integrity checks).
    - **`xml/`**: XML parsing and generation helpers.
    - **`dependencies/`**: Dependency collection for tree nodes.
    - **`utils/`**: Shared utilities and configuration helpers.
    - **`constants/`**: Type ordering and parser configuration.
    - **`cli/`**: Argument parsing, logging configuration.
- **`docs/roadmap.yaml`**: Tracks support status (implemented/planned) for different ABAP object types.
- **`scripts/`**: Utility and debug scripts (e.g., `integration-test.mjs`, `delete-package.ts`).

## Development Workflow

### Installation
```bash
npm install
```

### Build Commands
- **Full Build (Clean + Lint + Compile):**
  ```bash
  npm run build
  ```
- **Fast Build (Compile only):**
  ```bash
  npm run build:fast
  ```

### Linting & Formatting
The project uses **Biome**.
- **Check Lint:** `npm run lint:check`
- **Fix Lint:** `npm run lint`
- **Format:** `npm run format`

### Testing
- **Automated:** `npm run test:integration` (runs `scripts/integration-test.mjs`).
- **Manual:** Build the project and run the CLI against a test SAP system.
  ```bash
  node dist/bin/adt-backup.js <command> ...
  ```

## CLI Usage Reference
Common commands:
- **Backup Package:** `adt-backup backup --package <PKG> --output <FILE> --destination <DEST>`
- **Backup Tree (No Source):** `adt-backup tree --package <PKG> --output <FILE> --destination <DEST>`
- **Restore:** `adt-backup restore --input <FILE> --mode upsert --destination <DEST>`
- **Verify:** `adt-backup verify --input <FILE> --destination <DEST>`

## Coding Conventions
- **Style:** Adhere to Biome settings (2 spaces indentation, single quotes, semicolons).
- **Naming:** Explicit, descriptive names. CLI commands are lowercase.
- **Language:** All artifacts (code, comments, documentation) are in English; communication (chat, commit messages) is in Ukrainian.
- **Integrity:** Use checksums (`src/lib/crypto`) to ensure backup consistency.
- **Auth:** Never commit `.env` or auth config files. Use environment variables or local configs.

## Roadmap & Support
Refer to `docs/roadmap.yaml` for the current status of supported ABAP object types. Currently supports most core types including:
- Packages, Classes, Interfaces, Programs
- Function Groups & Modules
- Tables, Views, Data Elements, Domains, Table Types
- CDS (Data Definitions, Metadata Extensions, Service Definitions, Service Bindings)
- Behavior Definitions & Implementations
- Enhancements
- Unit Tests (Class-based and CDS)
