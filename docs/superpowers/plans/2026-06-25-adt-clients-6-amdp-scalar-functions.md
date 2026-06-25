# adt-clients 6.0.0 Migration + AMDP / Scalar / Table Functions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate the backup/restore CLI to `@mcp-abap-adt/adt-clients@^6.0.0` and add backup/restore of CDS DDL (incl. table functions), scalar functions (definition + implementation), and append structures — so AMDP classes, scalar functions and table functions restore as one co-activated group.

**Architecture:** Each ABAP object type is a `SupportedType` threaded through ~16 per-type registries (mapping, config, read, restore, ordering). The migration renames `view → ddl` (no alias) and adds `scalarFunction`, `scalarFunctionImplementation`, `appendStructure`. Co-activation is achieved by adding **bidirectional** structural edges in `buildAdjacency` so the related objects form a single SCC, which `analyzeDependencyLevels` emits as one restore group.

**Tech Stack:** TypeScript (strict, es2022, CommonJS), `@mcp-abap-adt/adt-clients` 6.0.0, `fast-xml-parser`, `yaml`, Biome (lint/format). No unit-test runner — verification is `npm run build` + offline CLI checks + a live smoke test.

## Global Constraints

- `@mcp-abap-adt/adt-clients` must be `^6.0.0`. `getView()` does not exist in 6.0.0; use `getDdl()`.
- All code, comments, commit messages in English. Commit summaries imperative, ≤72 chars, scope when useful.
- Biome style: 2-space indent, single quotes, semicolons, organized imports.
- No automated test framework. Per-task gate: `npm run build:fast && npm run lint:check` must pass. Final gate: `npm run build` (clean+lint+compile).
- `view → ddl` is a hard rename with **no backward alias**; old schemaVersion-2 backups containing `'view'` become unreadable (acceptable, documented).
- Payload formats: `ddl`, `scalarFunction`, `scalarFunctionImplementation`, `appendStructure` are all `source` (`codeFormat: 'source'`).
- Verified 6.0.0 config shapes (from the published tarball):
  - `IDdlConfig { ddlName: string; packageName?; transportRequest?; description?; ddlSource?; masterLanguage? }`
  - `IScalarFunctionConfig { scalarFunctionName: string; packageName?; transportRequest?; description?; sourceCode?; masterLanguage? }`
  - `type ScalarFunctionEngine = 'sqlEngine' | 'amdpEngine'`
  - `IScalarFunctionImplementationConfig { implementationName: string; scalarFunctionName: string; engineValue?: ScalarFunctionEngine; packageName?; transportRequest?; description?; sourceCode?; masterLanguage? }`
  - `IAppendStructureConfig { appendStructureName: string; baseObject?: string; packageName?; transportRequest?; description?; sourceCode?; masterLanguage? }`
  - All four clients expose `validate/create/read/readMetadata/update/delete/activate/lock/unlock` (same shape as the removed `AdtView`).

---

### Task 1: Install 6.0.0 and migrate `view` → `ddl`

Pure migration. Replace the `view` SupportedType with `ddl` everywhere and switch `getView()` calls to `getDdl()`. No new behavior; the build error list from the missing `getView()` is the migration checklist.

**Files:**
- Modify: `package.json` (dependency version)
- Modify: `src/lib/types.ts:8`
- Modify: `src/lib/utils/normalizeType.ts` (`view` entry)
- Modify: `src/lib/constants/typeOrder.ts:10`
- Modify: `src/lib/tree/isRestoreImplemented.ts`
- Modify: `src/lib/verify/findOtherType.ts`
- Modify: `src/lib/tree/mapAdtTypeToSupported.ts:22,53`
- Modify: `src/lib/dependencies/collectTreeDependencies.ts:16`
- Modify: `src/lib/restore/analyzeDependencies.ts:259`
- Modify: `src/lib/restore/restoreObjects.ts:15`
- Modify: `src/lib/utils/applyConfigName.ts:28-29`
- Modify: `src/lib/restore/restoreObject.ts:125-137` (+ import)
- Modify: `src/lib/restore/restoreTreeNode.ts:200-212` (+ import)
- Modify: `src/lib/backup/readSourceText.ts:36-41`
- Modify: `src/lib/backup/readMetadataXmlForType.ts:66-69`
- Modify: `src/lib/tree/readPayloadForType.ts:17`
- Modify: `src/lib/restore/restoreTreeBackup.ts:39`

**Interfaces:**
- Produces: SupportedType `'ddl'`; config name field `ddlName`; ADT mapping `DDLS/*` → `'ddl'`.

- [ ] **Step 1: Install adt-clients 6.0.0**

```bash
npm install @mcp-abap-adt/adt-clients@^6.0.0
```

- [ ] **Step 2: Confirm the migration surface via a failing build**

```bash
npm run build:fast
```
Expected: FAIL — TypeScript errors `Property 'getView' does not exist on type 'AdtClient'` at `restoreObject.ts`, `restoreTreeNode.ts`, `readSourceText.ts`, `readMetadataXmlForType.ts`. This is the to-do list.

- [ ] **Step 3: Rename the type in `types.ts`**

In `src/lib/types.ts` replace line `  | 'view'` with `  | 'ddl'`.

- [ ] **Step 4: Update `normalizeType.ts`**

Replace `    view: 'view',` with:

```ts
    ddl: 'ddl',
    view: 'ddl',
    cds: 'ddl',
```

(Accept legacy `view`/`cds` spellings on the CLI but normalize to the internal `ddl`.)

- [ ] **Step 5: Update `typeOrder.ts` and `isRestoreImplemented.ts` and `findOtherType.ts`**

In `src/lib/constants/typeOrder.ts` replace `'view',` with `'ddl',`.
In `src/lib/tree/isRestoreImplemented.ts` replace `case 'view':` with `case 'ddl':`.
In `src/lib/verify/findOtherType.ts` replace `'view',` with `'ddl',`.

- [ ] **Step 6: Update `mapAdtTypeToSupported.ts`**

Replace `    'DDLS/DF': 'view',` with `    'DDLS/DF': 'ddl',` and replace `  if (normalized.startsWith('DDLS/')) return 'view';` with `  if (normalized.startsWith('DDLS/')) return 'ddl';`.

- [ ] **Step 7: Update dependency/order maps**

In `src/lib/dependencies/collectTreeDependencies.ts` replace `  view: 'DDLS/DF',` with `  ddl: 'DDLS/DF',`.
In `src/lib/restore/analyzeDependencies.ts` replace `  view: 3,` with `  ddl: 3,`.
In `src/lib/restore/restoreObjects.ts` replace `  view: 'VIEW/DV',` with `  ddl: 'DDLS/DF',`.

- [ ] **Step 8: Update `applyConfigName.ts`**

Replace:

```ts
    case 'view':
      finalConfig.viewName = name;
      break;
```

with:

```ts
    case 'ddl':
      finalConfig.ddlName = name;
      break;
```

- [ ] **Step 9: Update `restoreObject.ts`**

Change the import `IViewConfig` → `IDdlConfig` in the import block (line 22). Replace the `case 'view'` block (lines 125-137) with:

```ts
    case 'ddl': {
      if (mode !== 'update') {
        await client.getDdl().create(asConfig<IDdlConfig>(config), options);
      }
      if (obj.source) {
        await client
          .getDdl()
          .update(
            asConfig<IDdlConfig>({ ...config, ddlSource: obj.source }),
            options,
          );
      }
      return;
    }
```

- [ ] **Step 10: Update `restoreTreeNode.ts`**

Change the `IViewConfig` import → `IDdlConfig`. Replace the `case 'view'` block (lines 200-212) with:

```ts
      case 'ddl': {
        if (mode !== 'update') {
          await client.getDdl().create(asConfig<IDdlConfig>(config), options);
        }
        if (payload) {
          await client
            .getDdl()
            .update(
              asConfig<IDdlConfig>({ ...config, ddlSource: payload }),
              options,
            );
        }
        return;
      }
```

- [ ] **Step 11: Update `readSourceText.ts`**

Replace the `case 'view'` block (lines 36-41) with:

```ts
      case 'ddl': {
        const state = await client
          .getDdl()
          .read({ ddlName: spec.name }, version);
        return responseToText(state?.readResult);
      }
```

- [ ] **Step 12: Update `readMetadataXmlForType.ts`**

Replace the `case 'view'` block (lines 66-69) with:

```ts
      case 'ddl': {
        const state = await client.getDdl().readMetadata({ ddlName: name });
        result = responseToText(state.metadataResult);
        break;
      }
```

- [ ] **Step 13: Update `readPayloadForType.ts` and `restoreTreeBackup.ts`**

In `src/lib/tree/readPayloadForType.ts` replace `    case 'view':` with `    case 'ddl':`.
In `src/lib/restore/restoreTreeBackup.ts` replace the phase line:

```ts
  { name: 'CDS Views', types: ['view'], activation: 'cluster' },
```

with:

```ts
  { name: 'DDL (CDS Views & Table Functions)', types: ['ddl'], activation: 'cluster' },
```

- [ ] **Step 14: Verify the build is green**

```bash
npm run build:fast && npm run lint:check
```
Expected: PASS, no `getView`/`view` references remain. Sanity check:

```bash
grep -rn "getView\|'view'\|viewName\|IViewConfig" src/ || echo "clean"
```
Expected: `clean`.

- [ ] **Step 15: Commit**

```bash
git add -A
git commit -m "feat: migrate to adt-clients 6.0.0 (view -> ddl)"
```

---

### Task 2: Add `scalarFunction` type (DSFD/SCF)

A source-payload object backed by `getScalarFunction()`. `buildConfigForNode`'s `default` branch already covers name + description + package, so no new parser is needed here.

**Files:**
- Modify: `src/lib/types.ts` (add union member)
- Modify: `src/lib/utils/normalizeType.ts`
- Modify: `src/lib/constants/typeOrder.ts`
- Modify: `src/lib/tree/isRestoreImplemented.ts`
- Modify: `src/lib/verify/findOtherType.ts`
- Modify: `src/lib/tree/mapAdtTypeToSupported.ts`
- Modify: `src/lib/dependencies/collectTreeDependencies.ts`
- Modify: `src/lib/restore/analyzeDependencies.ts` (`TYPE_CREATION_ORDER`)
- Modify: `src/lib/restore/restoreObjects.ts` (`ADT_TYPE_MAP`)
- Modify: `src/lib/utils/applyConfigName.ts`
- Modify: `src/lib/restore/restoreObject.ts`
- Modify: `src/lib/restore/restoreTreeNode.ts`
- Modify: `src/lib/backup/readSourceText.ts`
- Modify: `src/lib/backup/readMetadataXmlForType.ts`
- Modify: `src/lib/tree/readPayloadForType.ts`
- Modify: `src/lib/restore/restoreTreeBackup.ts` (`RESTORE_PHASES`)

**Interfaces:**
- Consumes: `'ddl'` type from Task 1.
- Produces: SupportedType `'scalarFunction'`; config name field `scalarFunctionName`; ADT mapping `DSFD/SCF` → `'scalarFunction'`.

- [ ] **Step 1: Add the type and aliases**

`src/lib/types.ts`: add `  | 'scalarFunction'` to the union.
`src/lib/utils/normalizeType.ts`: add to the map:

```ts
    scalarfunction: 'scalarFunction',
    scalar_function: 'scalarFunction',
```

`src/lib/constants/typeOrder.ts`: add `'scalarFunction',` after `'ddl',`.
`src/lib/tree/isRestoreImplemented.ts`: add `case 'scalarFunction':` to the `return true` group.
`src/lib/verify/findOtherType.ts`: add `'scalarFunction',` to the array.

- [ ] **Step 2: Add ADT mappings**

`src/lib/tree/mapAdtTypeToSupported.ts`: add to the exact-match map `    'DSFD/SCF': 'scalarFunction',` and add a prefix rule `  if (normalized.startsWith('DSFD/')) return 'scalarFunction';`.
`src/lib/dependencies/collectTreeDependencies.ts`: add `  scalarFunction: 'DSFD/SCF',` to `WHERE_USED_TYPE_MAP`.
`src/lib/restore/restoreObjects.ts`: add `  scalarFunction: 'DSFD/SCF',` to `ADT_TYPE_MAP`.

- [ ] **Step 3: Add creation order**

`src/lib/restore/analyzeDependencies.ts`: in `TYPE_CREATION_ORDER` add `  scalarFunction: 3,` (same level as `ddl`).

- [ ] **Step 4: Add config name field**

`src/lib/utils/applyConfigName.ts`: add:

```ts
    case 'scalarFunction':
      finalConfig.scalarFunctionName = name;
      break;
```

- [ ] **Step 5: Add read support**

`src/lib/backup/readSourceText.ts`: add before `default`:

```ts
      case 'scalarFunction': {
        const state = await client
          .getScalarFunction()
          .read({ scalarFunctionName: spec.name }, version);
        return responseToText(state?.readResult);
      }
```

`src/lib/backup/readMetadataXmlForType.ts`: add before `default`:

```ts
      case 'scalarFunction': {
        const state = await client
          .getScalarFunction()
          .readMetadata({ scalarFunctionName: name });
        result = responseToText(state.metadataResult);
        break;
      }
```

`src/lib/tree/readPayloadForType.ts`: add `    case 'scalarFunction':` to the `source` group (the block that calls `readSourceText`).

- [ ] **Step 6: Add restore support**

`src/lib/restore/restoreObject.ts`: add `IScalarFunctionConfig` to the import block and add before `default`:

```ts
    case 'scalarFunction': {
      if (mode !== 'update') {
        await client
          .getScalarFunction()
          .create(asConfig<IScalarFunctionConfig>(config), options);
      }
      if (obj.source) {
        await client
          .getScalarFunction()
          .update(
            asConfig<IScalarFunctionConfig>({ ...config, sourceCode: obj.source }),
            options,
          );
      }
      return;
    }
```

`src/lib/restore/restoreTreeNode.ts`: add `IScalarFunctionConfig` import and the analogous block using `payload` instead of `obj.source`:

```ts
      case 'scalarFunction': {
        if (mode !== 'update') {
          await client
            .getScalarFunction()
            .create(asConfig<IScalarFunctionConfig>(config), options);
        }
        if (payload) {
          await client
            .getScalarFunction()
            .update(
              asConfig<IScalarFunctionConfig>({ ...config, sourceCode: payload }),
              options,
            );
        }
        return;
      }
```

- [ ] **Step 7: Register in fallback phases**

`src/lib/restore/restoreTreeBackup.ts`: add a phase (fallback path only; ordering, not co-activation) before the `Classes` phase:

```ts
  {
    name: 'Scalar Functions',
    types: ['scalarFunction'],
    activation: 'cluster',
  },
```

- [ ] **Step 8: Verify and commit**

```bash
npm run build:fast && npm run lint:check
```
Expected: PASS.

```bash
git add -A
git commit -m "feat: support scalar function (DSFD) backup/restore"
```

---

### Task 3: Add `scalarFunctionImplementation` type (DSFI/SFI)

Implementation needs `scalarFunctionName` and `engineValue` at create time, captured from metadata XML. Requires a dedicated parser and a `buildConfigForNode` case.

**Files:**
- Create: `src/lib/xml/parseScalarFunctionImplementationConfig.ts`
- Modify: `src/lib/types.ts`, `src/lib/utils/normalizeType.ts`, `src/lib/constants/typeOrder.ts`, `src/lib/tree/isRestoreImplemented.ts`, `src/lib/verify/findOtherType.ts`
- Modify: `src/lib/tree/mapAdtTypeToSupported.ts`, `src/lib/dependencies/collectTreeDependencies.ts`, `src/lib/restore/restoreObjects.ts`, `src/lib/restore/analyzeDependencies.ts`
- Modify: `src/lib/utils/applyConfigName.ts`
- Modify: `src/lib/tree/buildConfigForNode.ts`
- Modify: `src/lib/backup/readSourceText.ts`, `src/lib/backup/readMetadataXmlForType.ts`, `src/lib/tree/readPayloadForType.ts`
- Modify: `src/lib/restore/restoreObject.ts`, `src/lib/restore/restoreTreeNode.ts`, `src/lib/restore/restoreTreeBackup.ts`

**Interfaces:**
- Consumes: `'scalarFunction'` from Task 2.
- Produces: SupportedType `'scalarFunctionImplementation'`; config fields `implementationName`, `scalarFunctionName`, `engineValue`; ADT mapping `DSFI/SFI` → `'scalarFunctionImplementation'`; `parseScalarFunctionImplementationConfig(xml): { scalarFunctionName?: string; engineValue?: 'sqlEngine' | 'amdpEngine'; description?: string; packageName?: string }`.

- [ ] **Step 1: Write the metadata parser**

Create `src/lib/xml/parseScalarFunctionImplementationConfig.ts`:

```ts
import { xmlParser } from '../constants/xmlParser';
import type { NodeValue } from '../types';
import { findAttribute } from './findAttribute';
import { extractMetadata } from './extractMetadata';

export function parseScalarFunctionImplementationConfig(xml: string): {
  scalarFunctionName?: string;
  engineValue?: 'sqlEngine' | 'amdpEngine';
  description?: string;
  packageName?: string;
} {
  const parsed = xmlParser.parse(xml) as NodeValue;
  const { description, packageName } = extractMetadata(xml);
  // ADT exposes the owning definition and the engine as attributes; names vary
  // by release, so probe the known candidates.
  const scalarFunctionName =
    findAttribute(parsed, 'dsfi:scalarFunction') ||
    findAttribute(parsed, 'scalarFunction') ||
    findAttribute(parsed, 'dsfi:functionName');
  const rawEngine =
    findAttribute(parsed, 'dsfi:engine') || findAttribute(parsed, 'engine');
  const engineValue =
    rawEngine === 'amdpEngine' || rawEngine === 'AMDP'
      ? 'amdpEngine'
      : 'sqlEngine';
  return { scalarFunctionName, engineValue, description, packageName };
}
```

> NOTE for the implementer: the exact attribute names are unverified (no live system at plan time). After the live smoke test (Task 6), correct the probed attribute names if `scalarFunctionName` comes back empty. This is a documented open risk in the spec.

- [ ] **Step 2: Add type, aliases, order, registries**

`src/lib/types.ts`: add `  | 'scalarFunctionImplementation'`.
`src/lib/utils/normalizeType.ts`: add `scalarfunctionimplementation: 'scalarFunctionImplementation',` and `scalar_function_implementation: 'scalarFunctionImplementation',`.
`src/lib/constants/typeOrder.ts`: add `'scalarFunctionImplementation',` after `'class',`.
`src/lib/tree/isRestoreImplemented.ts`: add `case 'scalarFunctionImplementation':`.
`src/lib/verify/findOtherType.ts`: add `'scalarFunctionImplementation',`.
`src/lib/tree/mapAdtTypeToSupported.ts`: add `    'DSFI/SFI': 'scalarFunctionImplementation',` and `  if (normalized.startsWith('DSFI/')) return 'scalarFunctionImplementation';`.
`src/lib/dependencies/collectTreeDependencies.ts`: add `  scalarFunctionImplementation: 'DSFI/SFI',`.
`src/lib/restore/restoreObjects.ts`: add `  scalarFunctionImplementation: 'DSFI/SFI',`.
`src/lib/restore/analyzeDependencies.ts`: add `  scalarFunctionImplementation: 6,` to `TYPE_CREATION_ORDER` (after `class: 5`).

- [ ] **Step 3: Add config name field**

`src/lib/utils/applyConfigName.ts`:

```ts
    case 'scalarFunctionImplementation':
      finalConfig.implementationName = name;
      break;
```

- [ ] **Step 4: Capture scalarFunctionName + engineValue at backup time**

`src/lib/tree/buildConfigForNode.ts`: add the import `import { parseScalarFunctionImplementationConfig } from '../xml/parseScalarFunctionImplementationConfig';` and a case before `default`:

```ts
    case 'scalarFunctionImplementation': {
      const base = applyConfigName(type, name, functionGroupName, {
        implementationName: name,
      } as BackupConfig);
      if (!metadataXml) {
        return { ...base, engineValue: 'sqlEngine' } as BackupConfig;
      }
      const parsed = parseScalarFunctionImplementationConfig(metadataXml);
      return {
        ...base,
        scalarFunctionName: parsed.scalarFunctionName,
        engineValue: parsed.engineValue ?? 'sqlEngine',
        description: parsed.description,
        packageName: parsed.packageName,
      } as BackupConfig;
    }
```

- [ ] **Step 5: Add read support**

`src/lib/backup/readSourceText.ts`: add before `default`:

```ts
      case 'scalarFunctionImplementation': {
        const state = await client
          .getScalarFunctionImplementation()
          .read({ implementationName: spec.name }, version);
        return responseToText(state?.readResult);
      }
```

`src/lib/backup/readMetadataXmlForType.ts`: add before `default`:

```ts
      case 'scalarFunctionImplementation': {
        const state = await client
          .getScalarFunctionImplementation()
          .readMetadata({ implementationName: name });
        result = responseToText(state.metadataResult);
        break;
      }
```

`src/lib/tree/readPayloadForType.ts`: add `    case 'scalarFunctionImplementation':` to the `source` group.

- [ ] **Step 6: Add restore support (passes scalarFunctionName + engineValue from config)**

`src/lib/restore/restoreObject.ts`: add `IScalarFunctionImplementationConfig` import and before `default`:

```ts
    case 'scalarFunctionImplementation': {
      if (mode !== 'update') {
        await client
          .getScalarFunctionImplementation()
          .create(asConfig<IScalarFunctionImplementationConfig>(config), options);
      }
      if (obj.source) {
        await client
          .getScalarFunctionImplementation()
          .update(
            asConfig<IScalarFunctionImplementationConfig>({
              ...config,
              sourceCode: obj.source,
            }),
            options,
          );
      }
      return;
    }
```

`src/lib/restore/restoreTreeNode.ts`: add the import and the analogous block using `payload`:

```ts
      case 'scalarFunctionImplementation': {
        if (mode !== 'update') {
          await client
            .getScalarFunctionImplementation()
            .create(asConfig<IScalarFunctionImplementationConfig>(config), options);
        }
        if (payload) {
          await client
            .getScalarFunctionImplementation()
            .update(
              asConfig<IScalarFunctionImplementationConfig>({
                ...config,
                sourceCode: payload,
              }),
              options,
            );
        }
        return;
      }
```

- [ ] **Step 7: Register in the Scalar Functions fallback phase**

`src/lib/restore/restoreTreeBackup.ts`: extend the `Scalar Functions` phase types from Task 2:

```ts
  {
    name: 'Scalar Functions',
    types: ['scalarFunction', 'scalarFunctionImplementation'],
    activation: 'cluster',
  },
```

- [ ] **Step 8: Verify and commit**

```bash
npm run build:fast && npm run lint:check
```
Expected: PASS.

```bash
git add -A
git commit -m "feat: support scalar function implementation (DSFI)"
```

---

### Task 4: Add `appendStructure` type (TABL/DS) + disambiguation

Append structures report ADT type `TABL/DS`, which `mapAdtTypeToSupported` currently maps to `structure`. Disambiguate so genuine structures still map to `structure` and only true appends map to `appendStructure`. `baseObject` is required at create time.

**Files:**
- Create: `src/lib/xml/parseAppendStructureConfig.ts`
- Modify: `src/lib/types.ts`, `src/lib/utils/normalizeType.ts`, `src/lib/constants/typeOrder.ts`, `src/lib/tree/isRestoreImplemented.ts`, `src/lib/verify/findOtherType.ts`
- Modify: `src/lib/tree/mapAdtTypeToSupported.ts`, `src/lib/dependencies/collectTreeDependencies.ts`, `src/lib/restore/restoreObjects.ts`, `src/lib/restore/analyzeDependencies.ts`
- Modify: `src/lib/utils/applyConfigName.ts`, `src/lib/tree/buildConfigForNode.ts`
- Modify: `src/lib/backup/readSourceText.ts`, `src/lib/backup/readMetadataXmlForType.ts`, `src/lib/tree/readPayloadForType.ts`
- Modify: `src/lib/restore/restoreObject.ts`, `src/lib/restore/restoreTreeNode.ts`, `src/lib/restore/restoreTreeBackup.ts`

**Interfaces:**
- Produces: SupportedType `'appendStructure'`; config fields `appendStructureName`, `baseObject`; `parseAppendStructureConfig(xml): { baseObject?: string; description?: string; packageName?: string }`.

- [ ] **Step 1: Write the metadata parser**

Create `src/lib/xml/parseAppendStructureConfig.ts`:

```ts
import { xmlParser } from '../constants/xmlParser';
import type { NodeValue } from '../types';
import { findAttribute } from './findAttribute';
import { extractMetadata } from './extractMetadata';

export function parseAppendStructureConfig(xml: string): {
  baseObject?: string;
  description?: string;
  packageName?: string;
} {
  const parsed = xmlParser.parse(xml) as NodeValue;
  const { description, packageName } = extractMetadata(xml);
  const baseObject =
    findAttribute(parsed, 'tabl:appendedTo') ||
    findAttribute(parsed, 'appendedTo') ||
    findAttribute(parsed, 'tabl:baseObject');
  return { baseObject, description, packageName };
}
```

> NOTE for the implementer: attribute names unverified at plan time; correct after the live smoke test if `baseObject` comes back empty.

- [ ] **Step 2: Add type, aliases, order, registries**

`src/lib/types.ts`: add `  | 'appendStructure'`.
`src/lib/utils/normalizeType.ts`: add `appendstructure: 'appendStructure',` and `append_structure: 'appendStructure',`.
`src/lib/constants/typeOrder.ts`: add `'appendStructure',` after `'table',`.
`src/lib/tree/isRestoreImplemented.ts`: add `case 'appendStructure':`.
`src/lib/verify/findOtherType.ts`: add `'appendStructure',`.
`src/lib/dependencies/collectTreeDependencies.ts`: add `  appendStructure: 'TABL/DS',`.
`src/lib/restore/restoreObjects.ts`: add `  appendStructure: 'TABL/DS',`.
`src/lib/restore/analyzeDependencies.ts`: add `  appendStructure: 3,` to `TYPE_CREATION_ORDER` (after its base table/structure at level 2).

- [ ] **Step 3: Disambiguate `TABL/DS` in `mapAdtTypeToSupported.ts`**

The function takes only the type string and cannot see the XML, so default `TABL/DS` to `structure` (preserving current behavior) and add an optional second argument used by callers that have already parsed the metadata. Change the signature and the `TABL/DS` handling:

```ts
export function mapAdtTypeToSupported(
  adtType?: string,
  hints?: { isAppend?: boolean },
): SupportedType | undefined {
  ...
  // exact-match map keeps 'TABL/DS': 'structure'
  ...
  if (normalized.startsWith('TABL/DS') || normalized.startsWith('STRU/')) {
    return hints?.isAppend ? 'appendStructure' : 'structure';
  }
```

Remove the old `if (map[normalized])` early-return for `TABL/DS` only if it shadows the hint — keep the map but let the prefix rule above run when `hints?.isAppend` is set. Concretely, guard the exact map lookup:

```ts
  if (map[normalized] && !(normalized === 'TABL/DS' && hints?.isAppend)) {
    return map[normalized];
  }
```

- [ ] **Step 4: Pass the append hint from the tree builder**

Find where `mapAdtTypeToSupported` is called during tree construction (`grep -rn "mapAdtTypeToSupported(" src/lib/tree/`). At the call site in `buildPackageBackupTree.ts`, detect appends from the ADT node. The package-hierarchy node carries a flag distinguishing appends (e.g. a `DS`-append marker or the node's `objectType` text containing `append`). Pass `{ isAppend }`:

```ts
const isAppend = /append/i.test(rawNode.type ?? '') || rawNode.appendStructure === true;
const supported = mapAdtTypeToSupported(rawNode.type, { isAppend });
```

> NOTE for the implementer: confirm the exact field carrying the append marker against the live `PackageHierarchyNode` during the smoke test; if appends are not distinguishable from the hierarchy, fall back to content inspection of the fetched metadata (`EXTEND`/append marker) inside `enrichTreeNode`.

- [ ] **Step 5: Add config name field + baseObject capture**

`src/lib/utils/applyConfigName.ts`:

```ts
    case 'appendStructure':
      finalConfig.appendStructureName = name;
      break;
```

`src/lib/tree/buildConfigForNode.ts`: add import `import { parseAppendStructureConfig } from '../xml/parseAppendStructureConfig';` and a case before `default`:

```ts
    case 'appendStructure': {
      const base = applyConfigName(type, name, functionGroupName, {
        appendStructureName: name,
      } as BackupConfig);
      if (!metadataXml) {
        return base;
      }
      const parsed = parseAppendStructureConfig(metadataXml);
      return {
        ...base,
        baseObject: parsed.baseObject,
        description: parsed.description,
        packageName: parsed.packageName,
      } as BackupConfig;
    }
```

- [ ] **Step 6: Add read support**

`src/lib/backup/readSourceText.ts`: add before `default`:

```ts
      case 'appendStructure': {
        const state = await client
          .getAppendStructure()
          .read({ appendStructureName: spec.name }, version);
        return responseToText(state?.readResult);
      }
```

`src/lib/backup/readMetadataXmlForType.ts`: add before `default`:

```ts
      case 'appendStructure': {
        const state = await client
          .getAppendStructure()
          .readMetadata({ appendStructureName: name });
        result = responseToText(state.metadataResult);
        break;
      }
```

`src/lib/tree/readPayloadForType.ts`: add `    case 'appendStructure':` to the `source` group.

- [ ] **Step 7: Add restore support with baseObject validation**

`src/lib/restore/restoreObject.ts`: add `IAppendStructureConfig` import and before `default`:

```ts
    case 'appendStructure': {
      if (mode !== 'update') {
        if (!config.baseObject) {
          throw new Error(
            `appendStructure ${obj.name}: missing baseObject (cannot create)`,
          );
        }
        await client
          .getAppendStructure()
          .create(asConfig<IAppendStructureConfig>(config), options);
      }
      if (obj.source) {
        await client
          .getAppendStructure()
          .update(
            asConfig<IAppendStructureConfig>({ ...config, sourceCode: obj.source }),
            options,
          );
      }
      return;
    }
```

`src/lib/restore/restoreTreeNode.ts`: add the import and the analogous block using `payload`, with the same `baseObject` guard before `create`.

- [ ] **Step 8: Register in fallback phases**

`src/lib/restore/restoreTreeBackup.ts`: add to the `Structures` phase or a dedicated one immediately after it:

```ts
  { name: 'Append Structures', types: ['appendStructure'], activation: 'individual' },
```

(Place after the `Tables` phase so the base object exists first.)

- [ ] **Step 9: Verify and commit**

```bash
npm run build:fast && npm run lint:check
```
Expected: PASS.

```bash
git add -A
git commit -m "feat: support append structure (TABL/DS) backup/restore"
```

---

### Task 5: Co-activation grouping — bidirectional SCC edges

Add structural edges in `buildAdjacency` so AMDP class + table-function DDLS + scalar definition + implementation collapse into one SCC, plus the reciprocal-edge mechanism so reverse edges survive the per-node `adj.set`.

**Files:**
- Modify: `src/lib/restore/analyzeDependencies.ts:16-102` (`buildAdjacency`)
- Create: `test/fixtures/amdp-group.backup.yaml` (offline verification fixture)

**Interfaces:**
- Consumes: types `ddl`, `class`, `scalarFunction`, `scalarFunctionImplementation`; node id format `` `${type}:${name}`.toUpperCase() `` (e.g. `CLASS:ZCL_X`, `DDL:ZTF`, `SCALARFUNCTION:ZSF`, `SCALARFUNCTIONIMPLEMENTATION:ZSFI`).
- Produces: single `RestoreGroup` containing the four related objects.

- [ ] **Step 1: Add the reverse-edge list and structural rules**

In `src/lib/restore/analyzeDependencies.ts`, modify `buildAdjacency`. Declare the reverse-edge collector before the loop (just after `const adj = new Map<string, Set<string>>();`):

```ts
  // Reverse edges to apply AFTER the loop, so the per-node adj.set() below
  // does not clobber them. Used to force co-activation SCCs where only one
  // side's source/config names the other (DDLS->class, DSFI->DSFD/class).
  const reverseEdges: Array<[string, string]> = [];
```

Inside the loop, after the existing structural rules (just before `adj.set(id, deps);` at the end), add:

```ts
    // Scalar function implementation -> definition (and reverse), via config.
    if (
      node.type === 'scalarFunctionImplementation' &&
      node.config?.scalarFunctionName
    ) {
      const defName = String(node.config.scalarFunctionName).toUpperCase();
      const defId = `SCALARFUNCTION:${defName}`;
      if (allIds.has(defId) && defId !== id) {
        deps.add(defId); // forward DSFI -> DSFD
        reverseEdges.push([defId, id]); // reverse DSFD -> DSFI
      }
    }

    // Reverse edges into AMDP classes that this DDLS / DSFI depends on, so the
    // class joins their activation SCC. Forward edges (this -> class) already
    // come from the source name-scan above. Restrict to class targets to avoid
    // dragging unrelated lower-level objects (data elements, domains) into the
    // group.
    if (node.type === 'ddl' || node.type === 'scalarFunctionImplementation') {
      for (const depId of deps) {
        if (depId.startsWith('CLASS:')) {
          reverseEdges.push([depId, id]);
        }
      }
    }
```

- [ ] **Step 2: Apply reverse edges by union after the loop**

Replace the final `return adj;` of `buildAdjacency` with:

```ts
  for (const [from, to] of reverseEdges) {
    const set = adj.get(from) ?? new Set<string>();
    set.add(to);
    adj.set(from, set);
  }

  return adj;
```

- [ ] **Step 3: Create the offline verification fixture**

Create `test/fixtures/amdp-group.backup.yaml`. The DDLS source must contain `IMPLEMENTED BY METHOD ZCL_AMDP=>GET` so the name-scan links the class; the implementation config carries `scalarFunctionName`. (`codeBase64` values below are base64 of the shown source.)

```yaml
schemaVersion: 2
package: ZTEST_AMDP
root:
  type: package
  name: ZTEST_AMDP
  restoreStatus: ok
  children:
    - type: class
      name: ZCL_AMDP
      restoreStatus: ok
      codeFormat: source
      # "CLASS zcl_amdp DEFINITION. METHOD get BY DATABASE FUNCTION. ENDCLASS."
      codeBase64: Q0xBU1MgemNsX2FtZHAgREVGSU5JVElPTi4gTUVUSE9EIGdldCBCWSBEQVRBQkFTRSBGVU5DVElPTi4gRU5EQ0xBU1Mu
    - type: ddl
      name: ZTF_DEMO
      restoreStatus: ok
      codeFormat: source
      # "define table function ZTF_DEMO ... implemented by method ZCL_AMDP=>GET;"
      codeBase64: ZGVmaW5lIHRhYmxlIGZ1bmN0aW9uIFpURl9ERU1PIHJldHVybnMgeyBrZXkgYWJhcC5pbnQ0OyB9IGltcGxlbWVudGVkIGJ5IG1ldGhvZCBaQ0xfQU1EUD0+R0VUOw==
    - type: scalarFunction
      name: ZSF_DEMO
      restoreStatus: ok
      codeFormat: source
      codeBase64: ZGVmaW5lIHNjYWxhciBmdW5jdGlvbiBaU0ZfREVNTw==
    - type: scalarFunctionImplementation
      name: ZSFI_DEMO
      restoreStatus: ok
      codeFormat: source
      config:
        implementationName: ZSFI_DEMO
        scalarFunctionName: ZSF_DEMO
        engineValue: sqlEngine
      codeBase64: aW1wbGVtZW50YXRpb24gWlNGSV9ERU1P
```

- [ ] **Step 4: Run `plan` offline against the fixture and assert one group**

```bash
npm run build:fast
node dist/bin/adt-backup.js plan --input test/fixtures/amdp-group.backup.yaml --output /tmp/amdp-plan.yaml
grep -nE "id:|type:|isCircular:" /tmp/amdp-plan.yaml
```
Expected: the non-package group (id ≥ 1) lists all four of `class ZCL_AMDP`, `ddl ZTF_DEMO`, `scalarFunction ZSF_DEMO`, `scalarFunctionImplementation ZSFI_DEMO` under a **single** group with `isCircular: true`. If they appear in separate groups, the SCC edges are wrong — fix before committing.

- [ ] **Step 5: Verify lint and commit**

```bash
npm run lint:check
git add -A
git commit -m "feat: co-activate AMDP/scalar/table-function as one restore group"
```

---

### Task 6: Live smoke test, docs, version bump, cleanup

**Files:**
- Modify: `docs/SMOKE_CHECKLIST.md`
- Modify: `docs/roadmap.yaml`
- Modify: `CLAUDE.md` (supported-type count/notes if stated)
- Modify: `package.json` (version), `CHANGELOG`/release notes if present
- Delete: `docs/superpowers/specs/2026-06-25-adt-clients-6-amdp-scalar-functions-design.md`, `docs/superpowers/plans/2026-06-25-adt-clients-6-amdp-scalar-functions.md`

**Interfaces:**
- Consumes: everything from Tasks 1-5.

- [ ] **Step 1: Full clean build**

```bash
npm run build
```
Expected: PASS (clean + lint + compile).

- [ ] **Step 2: Live smoke test (requires SAP connection)**

Against a test system with a package containing a table function + its AMDP class + a scalar function (definition + implementation) + an append structure:

```bash
node dist/bin/adt-backup.js backup --package ZTEST_AMDP --destination <sys> --output zb.yaml
node dist/bin/adt-backup.js plan --input zb.yaml --output zp.yaml
node dist/bin/adt-backup.js verify --plan zp.yaml --target <sys>
node dist/bin/adt-backup.js restore --plan zp.yaml --target <sys>
```
Verify: (a) backup captured `scalarFunctionImplementation` config `scalarFunctionName`/`engineValue` and `appendStructure` `baseObject` (inspect `zb.yaml`); (b) `zp.yaml` places the AMDP class + table function + scalar def + impl in one group; (c) restore creates them inactive and activates the group together with no activation error.

- [ ] **Step 3: Fix unverified attribute names if needed**

If Step 2 shows empty `scalarFunctionName` / `baseObject` / wrong `engineValue`, correct the probed attribute names in `parseScalarFunctionImplementationConfig.ts` / `parseAppendStructureConfig.ts` and the append detection in `buildPackageBackupTree.ts`, then re-run Step 2. Commit fixes:

```bash
git add -A
git commit -m "fix: correct DSFI/append metadata attribute names from live system"
```

- [ ] **Step 4: Update docs**

Add scalar/table-function/append entries to `docs/SMOKE_CHECKLIST.md` and mark the new types in `docs/roadmap.yaml` (payload format `source`). Update any supported-type count in `CLAUDE.md`.

- [ ] **Step 5: Bump version and delete the spec + plan**

Bump the minor version in `package.json` (this adds features). Then:

```bash
git rm docs/superpowers/specs/2026-06-25-adt-clients-6-amdp-scalar-functions-design.md
git rm docs/superpowers/plans/2026-06-25-adt-clients-6-amdp-scalar-functions.md
git add -A
git commit -m "docs: update checklist/roadmap; bump version; remove implemented spec/plan"
```

- [ ] **Step 6: Final verification**

```bash
npm run build
```
Expected: PASS.
