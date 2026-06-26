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
3. **Grouping via the existing SCC mechanism**, not a hard-coded "always one group"
   rule. Note (corrected after review): the SCC graph is built by `buildAdjacency` from
   source-scan + `config`-based structural edges, **not** from `usedBy`; see the
   Dependency grouping section for the exact edges added.
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

### How grouping actually works (corrected after review)

`node.usedBy` (populated by `collectTreeDependencies`) is **not** consumed by the SCC
builder. `analyzeDependencies()` / `analyzeDependencyLevels()` build their dependency
graph in `buildAdjacency()` (`src/lib/restore/analyzeDependencies.ts:16`) from two
sources only:

1. a regex scan of each node's decoded `codeBase64` for the names of other backup
   objects, and
2. explicit structural edges derived from `config` (the existing BDEF↔BIML / service
   binding cases at lines 53–95).

**A one-directional edge is not enough for co-activation.** `analyzeDependencyLevels`
(`src/lib/restore/analyzeDependencies.ts:276`) groups by DAG **level**: it computes each
SCC's level = `max(dependency level) + 1` and merges all SCCs *at the same level* into one
`RestoreGroup`. A one-directional edge A→B places B at a lower level than A, so they land
in **different** groups (correct ordering, but not co-activation). Objects co-activate in
one group only when they are in the **same SCC**.

Therefore, to satisfy the goal, the new objects must form a **single SCC** via
**bidirectional structural edges** in `buildAdjacency` — exactly the pattern already used
for `behaviorDefinition ↔ behaviorImplementation` (the code comment at line 53 states
"bidirectional = same SCC", with edges added in both directions at lines 54–75). Edges to
add (both directions each):

- **AMDP class ↔ table function (DDLS):** the DDLS source contains
  `IMPLEMENTED BY METHOD <class>=><method>`, giving the DDLS→class direction via the
  source name-scan; the **reverse** class→DDLS edge must be added from the DDLS node's
  iteration (the class source does not name the DDLS).
- **scalar function definition (DSFD) ↔ implementation (DSFI):** add both edges from the
  implementation's iteration using `config.scalarFunctionName` (the definition name is
  not reliably in either source): forward DSFI→DSFD and reverse DSFD→DSFI.
- **AMDP class ↔ DSFI (amdpEngine):** the `amdpEngine` implementation source names the
  AMDP class/method, so the source name-scan yields DSFI→class; add the reverse
  class→DSFI from the DSFI node's iteration. (`sqlEngine` implementations have no AMDP
  class, so no edge.) **Live-verify** that the class name actually appears in the DSFI
  source; there is no AMDP-class field in `IScalarFunctionImplementationConfig`, so no
  config-based fallback is assumed.

### Reciprocal-edge mechanism (required)

`buildAdjacency` currently builds only the *current* node's forward deps and overwrites
with `adj.set(id, deps)` at the end of each iteration
(`src/lib/restore/analyzeDependencies.ts:98`). The BDEF↔BIML pattern works **only because
each side's source names the other** (two independent forward edges). The new edges above
are one-sided: only the DDLS/DSFI source names its target, so the reverse edge must be
written into the **target** node's adjacency set — which the per-node overwrite would
clobber. The implementation must therefore:

- collect reverse edges discovered during the pass into a separate list
  `reverseEdges: Array<[fromId, toId]>`, and
- after the main loop, apply them by **union** into the existing adjacency sets
  (`adj.get(fromId)` ∪ `{toId}`, lazily creating the set), so nothing is overwritten.

A second full pass is an acceptable alternative; the requirement is that reciprocal edges
survive the per-node `adj.set`.

Net effect: the bidirectional edges produce **two SCCs** — `{ddl, class}` and
`{scalarFunction, scalarFunctionImplementation}` — rather than a single SCC spanning all
four objects. These two SCCs land in **one `RestoreGroup`** only because
`analyzeDependencyLevels` merges all SCCs that share the same DAG level. If one pair gains
a dependency that shifts its level (e.g. the table-function DDL depends on a backed-up DDIC
type that is itself at a higher level), the two SCCs may be emitted as separate groups.
Restore correctness is still preserved: each circular pair is bulk-activated atomically, and
cross-group ordering derived from the DAG is correct. `TYPE_CREATION_ORDER` governs the
create order *within* each group.

`WHERE_USED_TYPE_MAP` / `mapAdtTypeToSupported` entries for `DSFD/SCF`, `DSFI/SFI`,
`TABL/DS` are still added so `usedBy` stays complete for `diff`/display, but they are
**informational**, not the grouping mechanism.

### Where the co-activation guarantee holds (scoped after review)

- **Plan-driven restore (`restore --plan`, the canonical workflow):** `plan` calls
  `analyzeDependencyLevels` over all non-package nodes. Mixed-type analysis alone does
  **not** produce a mixed group — co-activation happens only because the bidirectional
  edges above force the AMDP class + table function + scalar def + impl into **one SCC**,
  which `analyzeDependencyLevels` emits as a single `RestoreGroup`. `restoreTreeBackup`
  then creates every object in that group inactive and `bulkActivate`s the whole group
  together (`src/lib/restore/restoreTreeBackup.ts:330`). This co-activation is therefore
  contingent on the SCC edges, and the smoke test must assert the single group in the
  generated `plan.yaml`.
- **Fallback phase restore (no plan):** `RESTORE_PHASES` processes types in separate
  phases with per-phase activation, so cross-type co-activation does **not** happen
  there. We intentionally do **not** reshape `RESTORE_PHASES` (YAGNI); the spec documents
  this as a known limitation and the smoke test exercises the plan-driven path.

Intra-group creation order (`TYPE_CREATION_ORDER`):
`scalarFunction` (def) and `ddl` before `class`, `class` before
`scalarFunctionImplementation`; `appendStructure` after its base table/structure.

## Task 0 — install & verify 6.0.0 typings (do this first)

Local `node_modules` is still 5.8.0; nothing below is type-checked locally until this
runs. First step of implementation:

- `npm install @mcp-abap-adt/adt-clients@^6.0.0`, then `npm run build` to confirm the
  removal of `getView()` surfaces as compile errors at every call site (acts as a
  to-do list for the migration).

Verified 6.0.0 signatures (extracted from the published tarball during design):

```ts
// AdtClient getters present in 6.0.0 (getView() removed):
getDdl(), getScalarFunction(), getScalarFunctionImplementation(), getAppendStructure()

interface IDdlConfig { ddlName: string; packageName?; transportRequest?; description?; ddlSource?; masterLanguage?; }
interface IScalarFunctionConfig { scalarFunctionName: string; packageName?; transportRequest?; description?; sourceCode?; masterLanguage?; }
type ScalarFunctionEngine = 'sqlEngine' | 'amdpEngine';
interface IScalarFunctionImplementationConfig {
  implementationName: string; scalarFunctionName: string; engineValue?: ScalarFunctionEngine;
  packageName?; transportRequest?; description?; sourceCode?; masterLanguage?;
}
interface IAppendStructureConfig { appendStructureName: string; baseObject?: string; packageName?; transportRequest?; description?; sourceCode?; masterLanguage?; }
// All four clients expose: validate/create/read/readMetadata/update/delete/activate/lock/unlock
// (same shape as the removed AdtView).
```

## Touchpoints (~16 per-type registries)

- `src/lib/types.ts` — drop `view`; add `ddl`, `scalarFunction`,
  `scalarFunctionImplementation`, `appendStructure`.
- `src/lib/tree/mapAdtTypeToSupported.ts` — `DDLS/*` → `ddl`; add `DSFD/SCF`,
  `DSFI/SFI`; resolve `TABL/DS` ambiguity (see risks).
- `src/lib/utils/normalizeType.ts` — drop `view`, add new aliases.
- `src/lib/utils/applyConfigName.ts` — config name fields: `ddlName`,
  `scalarFunctionName`, `implementationName`, `appendStructureName`.
- `src/lib/tree/buildConfigForNode.ts` + new XML parsers — `applyConfigName` only sets
  the *name* field; non-name `create` parameters must be captured from metadata XML here:
  - **`appendStructure.baseObject`** — parse from the append-structure metadata XML
    (new `parseAppendStructureConfig`); restore must validate it is non-empty before
    calling `getAppendStructure().create`, failing the action with a clear message
    otherwise.
  - **`scalarFunctionImplementation.scalarFunctionName`** — parse from the implementation
    metadata XML (new `parseScalarFunctionImplementationConfig`); also capture
    **`engineValue`** here, defaulting to `'sqlEngine'` when the system reports none.
  These two configs are also what the `buildAdjacency` structural edges read, so they
  must be populated at backup time, not only at restore time.
- `src/lib/restore/restoreObject.ts` & `restoreTreeNode.ts` — create/update switch cases
  via the 6.0.0 clients.
- `src/lib/restore/restoreObjects.ts` — type→ADT-type map for activation refs.
- `src/lib/backup/readSourceText.ts` — `getDdl().read` (was `getView`), plus new types.
- `src/lib/backup/readMetadataXmlForType.ts` — `readMetadata` for new types; capture
  `engineValue` for scalar function implementation.
- `src/lib/tree/readPayloadForType.ts` — payload selection for new types.
- `src/lib/tree/isRestoreImplemented.ts` — mark new types implemented.
- `src/lib/dependencies/collectTreeDependencies.ts` — `WHERE_USED_TYPE_MAP` entries.
- `src/lib/restore/analyzeDependencies.ts` — `TYPE_CREATION_ORDER` weights for the new
  types; add the bidirectional structural edges in `buildAdjacency` (DDLS↔class,
  DSFD↔DSFI, class↔DSFI-amdp) **plus** the reciprocal-edge mechanism (reverse-edge list
  unioned after the main loop) described in the Dependency grouping section.
- `src/lib/restore/restoreTreeBackup.ts` — **fallback path only**: rename the `CDS Views`
  phase → `DDL` and register the new types (`scalarFunction`,
  `scalarFunctionImplementation`, `appendStructure`) in `RESTORE_PHASES` so the no-plan
  restore handles them at all. This is registration/ordering only — it does **not** add
  cross-type cluster activation to the fallback path (that remains plan-driven, per the
  decision above). The plan-driven path needs no change here; it follows `plan.groups`.
- `src/lib/constants/typeOrder.ts` — `view` → `ddl`; add new types.
- `src/lib/verify/findOtherType.ts` — `view` → `ddl`; add new types.
- `package.json` — `@mcp-abap-adt/adt-clients` `^6.0.0`.

## Risks / open implementation questions

- **`TABL/DS` ambiguity.** `mapAdtTypeToSupported` currently maps `TABL/DS` → `structure`
  (with a code comment that ADT sometimes returns `TABL/DS` for structures). Append
  structures also report `TABL/DS`. The implementation must disambiguate — likely by a
  more specific ADT subtype or by source-content inspection — without regressing existing
  structure handling. Resolve during implementation/verification against the live system.
- **Scalar function def/impl pairing** depends on the bidirectional `buildAdjacency`
  edges keyed on `config.scalarFunctionName` — verify on a live system that the
  implementation's metadata XML actually exposes the definition name; if it does not, the
  def/impl pair will not share an SCC and the spec's grouping approach needs revisiting.
- **Grouping edges are unverified against a live system.** Confirm that the table
  function DDLS source contains the AMDP class name (for the source name-scan) and that
  the DSFI metadata exposes `scalarFunctionName`/`engineValue`. If an edge is missing,
  the objects split into separate plan groups and activate separately.
- **Co-activation only in plan-driven restore.** The fallback phase restore does not
  co-activate these types across phases (documented limitation, not fixed here).

## Testing

- `npm run build` (clean + lint + compile) and `npm run lint:check` must pass.
- Manual validation per `docs/SMOKE_CHECKLIST.md` on a live SAP system, exercising the
  **plan-driven** path: back up a package containing a table function + its AMDP class +
  a scalar function (definition + implementation), then `plan` → `verify` →
  `restore --plan`, confirming the AMDP/scalar/table-function objects land in **one plan
  group** (inspect the generated `plan.yaml`) and are bulk-activated together. Also
  confirm the backup captured `appendStructure.baseObject` and
  `scalarFunctionImplementation.scalarFunctionName`/`engineValue`.
