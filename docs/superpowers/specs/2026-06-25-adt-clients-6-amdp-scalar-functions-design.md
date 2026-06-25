# Design: Migrate to adt-clients 6.0.0 + AMDP / scalar / table functions

Date: 2026-06-25
Status: Approved (pending spec review)

## Goal

Migrate the backup/restore CLI from `@mcp-abap-adt/adt-clients` `^5.8.0` to `^6.0.0`
and add support for the new object types exposed by 6.0.0, so that AMDP classes,
scalar functions and CDS table functions can be backed up and restored — with their
mutual dependencies restored and activated together as one group.

## Background: what changed in adt-clients 6.0.0

- **`getView()` was removed**, replaced by **`getDdl()`** (config `{ ddlName }`,
  ADT type `DDLS/DF`). `getDdl()` covers both CDS views and CDS **table functions**
  (both are DDLS sources).
- New clients:
  - **`getScalarFunction()`** — `{ scalarFunctionName }`, ADT type `DSFD/SCF`.
  - **`getScalarFunctionImplementation()`** — `{ implementationName,
    scalarFunctionName, engineValue }`, ADT type `DSFI/SFI`,
    `engineValue: 'sqlEngine' | 'amdpEngine'`.
  - **`getAppendStructure()`** — `{ appendStructureName, baseObject }`, ADT type `TABL/DS`.
  - `AmdpDebugger` (runtime; not used by this tool).
- All new clients share the same interface shape as existing core clients
  (`validate / create / read / readMetadata / update / delete / activate / lock / unlock`),
  so wiring is mechanical.

AMDP classes and CDS table functions need **no new internal type**: an AMDP class is a
regular `class` (`CLAS/OC`); a table function is a DDLS source, i.e. the `ddl` type.

## Decisions (confirmed with user)

1. **Single release** — migration + new types + grouping ship together.
2. **`view` → `ddl`, no backward alias.** Existing schemaVersion-2 backups that contain
   `'view'` nodes become unreadable and require a re-backup. This is acceptable.
3. **Grouping via where-used dependency analysis** (the existing SCC mechanism), not a
   hard-coded rule.
4. **Include `appendStructure`** in this release.
5. **Persist `engineValue`** of a scalar function implementation in the node `config`
   (it is a required `create` parameter). Capture the actual value reported by the
   system, defaulting to `sqlEngine` when absent. The verified/working path for now is
   `sqlEngine`; the backup format still preserves `amdpEngine` if encountered.

## New / changed SupportedType values

| Internal type                    | ADT type    | Payload format | 6.0.0 client                          |
| -------------------------------- | ----------- | -------------- | ------------------------------------- |
| `ddl` (replaces `view`)          | `DDLS/DF`   | `source`       | `getDdl()` — CDS views & table funcs  |
| `scalarFunction`                 | `DSFD/SCF`  | `source`       | `getScalarFunction()`                 |
| `scalarFunctionImplementation`   | `DSFI/SFI`  | `source`       | `getScalarFunctionImplementation()`   |
| `appendStructure`                | `TABL/DS`   | `source`       | `getAppendStructure()`                |

Scalar function = one definition (`DSFD`) + one or more implementations (`DSFI`).
The implementation node stores `scalarFunctionName` and `engineValue` in its config.

## Dependency grouping (one activation cluster)

The restore already groups objects into SCC-based clusters via `analyzeDependencies()`
(Tarjan SCC + DAG ordering) and bulk-activates each cluster together. To make the new
objects land in the same cluster as the AMDP class / table function they belong to:

- `WHERE_USED_TYPE_MAP` (collectTreeDependencies) gains `DSFD/SCF`, `DSFI/SFI`,
  `TABL/DS` (`DDLS/DF` already present).
- `mapAdtTypeToSupported` resolves these ADT strings to the new internal types, so the
  where-used edges resolve to real nodes.
- Result: a table-function DDLS → AMDP class method, and scalar def ← impl → AMDP class,
  fall into the same SCC and are created inactive then bulk-activated together.

Intra-cluster creation order (`TYPE_CREATION_ORDER`):
`scalarFunction` (def) and `ddl` before `class`, `class` before
`scalarFunctionImplementation`; `appendStructure` after its base table/structure.

## Touchpoints (~16 per-type registries)

- `src/lib/types.ts` — drop `view`; add `ddl`, `scalarFunction`,
  `scalarFunctionImplementation`, `appendStructure`.
- `src/lib/tree/mapAdtTypeToSupported.ts` — `DDLS/*` → `ddl`; add `DSFD/SCF`,
  `DSFI/SFI`; resolve `TABL/DS` ambiguity (see risks).
- `src/lib/utils/normalizeType.ts` — drop `view`, add new aliases.
- `src/lib/utils/applyConfigName.ts` — config name fields: `ddlName`,
  `scalarFunctionName`, `implementationName`, `appendStructureName`.
- `src/lib/restore/restoreObject.ts` & `restoreTreeNode.ts` — create/update switch cases
  via the 6.0.0 clients.
- `src/lib/restore/restoreObjects.ts` — type→ADT-type map for activation refs.
- `src/lib/backup/readSourceText.ts` — `getDdl().read` (was `getView`), plus new types.
- `src/lib/backup/readMetadataXmlForType.ts` — `readMetadata` for new types; capture
  `engineValue` for scalar function implementation.
- `src/lib/tree/readPayloadForType.ts` — payload selection for new types.
- `src/lib/tree/isRestoreImplemented.ts` — mark new types implemented.
- `src/lib/dependencies/collectTreeDependencies.ts` — `WHERE_USED_TYPE_MAP` entries.
- `src/lib/restore/analyzeDependencies.ts` — `TYPE_CREATION_ORDER` weights.
- `src/lib/restore/restoreTreeBackup.ts` — rename `CDS Views` phase → `DDL`; add scalar
  function handling within cluster activation.
- `src/lib/constants/typeOrder.ts` — `view` → `ddl`; add new types.
- `src/lib/verify/findOtherType.ts` — `view` → `ddl`; add new types.
- `package.json` — `@mcp-abap-adt/adt-clients` `^6.0.0`.

## Risks / open implementation questions

- **`TABL/DS` ambiguity.** `mapAdtTypeToSupported` currently maps `TABL/DS` → `structure`
  (with a code comment that ADT sometimes returns `TABL/DS` for structures). Append
  structures also report `TABL/DS`. The implementation must disambiguate — likely by a
  more specific ADT subtype or by source-content inspection — without regressing existing
  structure handling. Resolve during implementation/verification against the live system.
- **Scalar function def/impl pairing** must survive backup → plan → restore so the
  implementation is created after its definition and after the AMDP class.
- Verify against a live system that the where-used lists for DSFD/DSFI/DDLS actually
  return the AMDP class edges; if not, grouping falls back to per-object activation.

## Testing

- `npm run build` (clean + lint + compile) and `npm run lint:check` must pass.
- Manual validation per `docs/SMOKE_CHECKLIST.md` on a live SAP system: back up a
  package containing a table function + its AMDP class + a scalar function
  (definition + implementation), then `plan` → `verify` → `restore`, confirming the
  AMDP/scalar/table-function objects land in one restore group and activate together.
