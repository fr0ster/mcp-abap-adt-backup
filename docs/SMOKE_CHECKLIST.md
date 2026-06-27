# Smoke Checklist

This checklist is for manual validation after landscape/auth setup is ready.

## Prerequisites

1. Build is up to date:
```bash
npm run build
```
2. Auth is configured and valid for your destination:
```bash
adt-backup --help
```
3. Use a writable temp folder:
```bash
mkdir -p /tmp/adt-backup-smoke
```

## 1) Backup: package tree

```bash
adt-backup backup \
  --package <PACKAGE_NAME> \
  --output /tmp/adt-backup-smoke/package_backup.yaml \
  --destination <DESTINATION> -vv
```

Expected:
- command exits with code `0`
- backup file exists and is non-empty

## 2) Validate: backup integrity

```bash
adt-backup validate \
  --input /tmp/adt-backup-smoke/package_backup.yaml
```

Expected:
- `Backup validated`

## 3) Verify: compare with system

```bash
adt-backup verify \
  --input /tmp/adt-backup-smoke/package_backup.yaml \
  --destination <DESTINATION> -vv
```

Expected:
- no unexpected `missing` / `type-mismatch` entries

## 4) Service Binding: focused backup/validate/verify

```bash
adt-backup backup \
  --objects serviceBinding:<SERVICE_BINDING_NAME> \
  --output /tmp/adt-backup-smoke/service_binding_backup.yaml \
  --destination <DESTINATION> -vv
```

```bash
adt-backup validate \
  --input /tmp/adt-backup-smoke/service_binding_backup.yaml
```

```bash
adt-backup verify \
  --input /tmp/adt-backup-smoke/service_binding_backup.yaml \
  --destination <DESTINATION> -vv
```

Expected:
- all three commands exit with code `0`

## 5) Restore: upsert dry smoke

Use a safe target package/object set that is allowed for update.

```bash
adt-backup restore \
  --input /tmp/adt-backup-smoke/package_backup.yaml \
  --mode upsert \
  --destination <DESTINATION> \
  --force -vv
```

Expected:
- restore passes without runtime errors

## 6) Post-restore verification

```bash
adt-backup verify \
  --input /tmp/adt-backup-smoke/package_backup.yaml \
  --destination <DESTINATION> -vv
```

Expected:
- no regressions compared to step 3

## 7) Optional diff check

```bash
adt-backup diff \
  --input /tmp/adt-backup-smoke/package_backup.yaml \
  --all \
  --destination <DESTINATION> -vv
```

Expected:
- output matches expected local/system differences

## 8) AMDP / scalar functions / table functions / append structure

Use a package that contains: a table-function CDS view (DDLS backed by an AMDP class), a scalar function definition (DSFD/SCF) + implementation (DSFI/SFI), and an append structure (TABL/DS).

```bash
adt-backup backup \
  --package <AMDP_PACKAGE> \
  --output /tmp/adt-backup-smoke/amdp_backup.yaml \
  --destination <DESTINATION> -vv
```

```bash
adt-backup plan \
  --input /tmp/adt-backup-smoke/amdp_backup.yaml \
  --output /tmp/adt-backup-smoke/amdp_plan.yaml
```

Expected:
- Each circular pair co-activates atomically: `{ddl, class}` share one SCC and `{scalarFunction, scalarFunctionImplementation}` share another. Both pairs normally appear in one restore group (same DAG level); splitting into two adjacent groups is acceptable as long as each pair stays together with `isCircular: true` and cross-group ordering is correct.
- The backup file captures `scalarFunctionImplementation` config fields `scalarFunctionName` and `engineValue`
- The backup file captures `appendStructure` config field `baseObject`
- **GATING CHECK — append-structure classification**: confirm that the append object appears in the backup as an `appendStructure` node (NOT `structure`) with a populated `baseObject` field. If it instead shows up as `structure`, the append-detection heuristic in `enrichTreeNode.ts` did not fire (no append marker in the hierarchy response); in that case, add a content-inspection fallback (detect the DDIC EXTEND/append marker in the fetched metadata XML) before the type is resolved.
- **NOTE**: The flat `--objects` path now captures `scalarFunctionName`/`engineValue` for `scalarFunctionImplementation` and `baseObject` for `appendStructure`, and **fails loudly** if a required field cannot be extracted from source. The `--package` path warns and marks the node `not-implemented` instead of aborting the whole walk.
