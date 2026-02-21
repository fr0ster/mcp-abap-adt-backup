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
