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

## Architecture

### Entry Point
- `src/bin/adt-backup.ts` - CLI entry, delegates to `src/lib/run.ts`
- `src/lib/run.ts` - Main command dispatcher handling all CLI commands

### Core Modules (`src/lib/`)

**auth/** - Authentication via `@mcp-abap-adt/auth-broker` ecosystem
- Supports destination-based auth (`--destination`) or `.env` file auth (`--env`)

**backup/** - Object backup logic
- `backupObject.ts` - Creates BackupObject from ADT
- `readSourceText.ts` - Fetches source code for objects
- `readMetadataXmlForType.ts` - Fetches metadata XML

**restore/** - Object restoration
- `restoreObject.ts` - Core restore logic per object type
- `restoreTreeBackup.ts` - Restores full package tree
- `sortByDependencies.ts` / `sortTreeNodesByDependencies.ts` - Dependency ordering

**tree/** - Package tree operations
- `buildPackageBackupTree.ts` - Recursively builds backup tree for package
- `enrichTreeNode.ts` - Adds payload/config to tree nodes
- `mapAdtTypeToSupported.ts` - Maps ADT types to internal `SupportedType`

**verify/** - Backup verification against live system
- `verifyBackup.ts` - Compares backup to current system state
- `verifyObjectInSystem.ts` - Checks single object existence/state

**xml/** - XML parsing utilities for ADT responses
- Uses `fast-xml-parser` for parsing
- `extractMetadata.ts` - Extracts common metadata fields

**crypto/** - Checksums for backup integrity
- Tree checksums (`updateTreeChecksums`, `verifyTreeChecksums`)
- Backup file checksums (`computeBackupChecksum`, `verifyBackupChecksum`)

### Data Types (`src/lib/types.ts`)

- `SupportedType` - Union of all supported ABAP object types
- `BackupFile` (schemaVersion 1) - Flat list of objects
- `BackupTreeFile` (schemaVersion 2) - Hierarchical package structure
- `BackupTreeNode` - Node in tree with optional `codeBase64`, `config`, `children`

### Supported Object Types

See `docs/roadmap.yaml` for backup/restore status per type. Key implemented types:
- package, domain, dataElement, structure, table, view
- class, interface, program
- functionGroup, functionModule
- serviceDefinition, metadataExtension

## CLI Commands

- `backup` - Create backup (package or individual objects)
- `restore` - Restore objects to SAP system
- `verify` - Check backup against live system
- `diff` - Show differences between backup and system
- `list` - List objects in backup file
- `extract` - Extract single object payload to file
- `patch` - Update object payload in backup file
- `validate` - Verify backup file integrity (checksums)

## Code Style

- Biome for linting/formatting (2-space indent, single quotes, semicolons)
- TypeScript strict mode
- No explicit `any` in production code (warnings allowed in tests)

## Key Dependencies

- `@mcp-abap-adt/adt-clients` - ADT API client
- `@mcp-abap-adt/connection` - ABAP connection handling
- `@mcp-abap-adt/auth-broker` - Authentication management
- `fast-xml-parser` - XML parsing
- `yaml` - YAML serialization for backup files
