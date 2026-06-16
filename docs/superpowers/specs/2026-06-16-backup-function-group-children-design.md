# Backup a function group's children (FMs + includes) — design

**Scope:** `mcp-abap-adt-backup` — when backing up a package recursively, capture
a function group's **function modules** and **includes**, not just the FUGR
metadata. Consumes the read-only enumeration added in `@mcp-abap-adt/adt-clients`
5.7.0 (`getUtils().listFunctionModules` / `listFunctionGroupIncludes`).

## Why

`getPackageHierarchy` returns FUGR nodes but **not** their children — function
modules (`FUGR/FF`) and includes (`FUGR/I`) are reachable only via a
nodestructure drill-down, now exposed by adt-clients. Today a package backup
captures the FUGR's metadata XML but drops the FM and include source — an
incomplete backup. (Verified: package recursion shows a FUGR with no children.)

## Mechanism

In `src/lib/tree/enrichTreeNode.ts`, when the node maps to `functionGroup` and
`includeCode` is set, enumerate and attach children before the existing
recursive child walk:

1. `client.getUtils().listFunctionModules(node.name)` → for each name, a child
   `{ name, adtType: 'FUGR/FF', type: 'functionModule', functionGroupName: node.name }`.
2. `client.getUtils().listFunctionGroupIncludes(node.name)` → for each name, a
   child `{ name, adtType: 'FUGR/I', type: 'functionInclude', functionGroupName: node.name }`,
   **excluding the generated collector** `L<FUGR>UXX` (exact name
   `` `L${node.name}UXX` `` , case-insensitive — not a fuzzy heuristic). The TOP
   include (`L<FUGR>TOP`, global data) and any custom includes are kept. The
   generated main program `SAPL<FUGR>` is not returned by `listFunctionGroupIncludes`
   (it is `FUGR/PX`), so no extra filtering is needed for it.
3. Merge enumerated children with any pre-existing `node.children`, then run the
   existing per-child `enrichTreeNode` recursion (which reads each child's source
   via `readPayloadForType`).

Enumeration runs once per function group (two ADT calls). FM names are NOT the
`L<FUGR>U01…` includes (those are `FUGR/FF` function modules, returned by
`listFunctionModules`, not by `listFunctionGroupIncludes`), so there is no overlap
or double-capture between the two lists.

## Changes

1. **`src/lib/types.ts`** — add `'functionInclude'` to the `SupportedType` union.
2. **`src/lib/tree/mapAdtTypeToSupported.ts`** — map `FUGR/I → functionInclude`
   (both the exact-key entry and the `startsWith('FUGR/I')` fallback, placed
   BEFORE the existing `startsWith('FUGR/')` → `functionGroup` catch-all so it
   is not shadowed).
3. **`src/lib/backup/readSourceText.ts`** — new `case 'functionInclude'`:
   ```ts
   case 'functionInclude': {
     if (!spec.functionGroupName) return undefined;
     const state = await client.getFunctionInclude().read(
       { functionGroupName: spec.functionGroupName, functionIncludeName: spec.name },
       version,
     );
     return responseToText(state?.readResult);
   }
   ```
   (Confirm the exact `getFunctionInclude().read()` param names against
   adt-clients `IFunctionIncludeConfig` during implementation; adjust if they
   differ.)
4. **`src/lib/tree/readPayloadForType.ts`** — route `functionInclude` to the new
   `readSourceText` case (mirror the `functionModule` wiring, passing
   `functionGroupName`).
5. **`src/lib/tree/isRestoreImplemented.ts`** — `functionInclude → false`
   (capture source now; restore wired separately later). Backed-up include nodes
   carry `restoreStatus: 'not-implemented'`.
6. **`src/lib/tree/enrichTreeNode.ts`** — the enumeration + merge described above.
7. **`src/lib/tree/buildConfigForNode.ts`** — a minimal `functionInclude` config
   (name + functionGroupName + description) so the node serializes consistently,
   if the build path requires a config for every typed node. Verify whether an
   unconfigured node is acceptable first; only add if needed.
8. **`package.json`** — bump `@mcp-abap-adt/adt-clients` from `^5.4.1` to `^5.7.0`
   (the version exposing the enumeration). `rm -rf node_modules/@mcp-abap-adt/adt-clients`
   + reinstall to avoid a stale copy.

## Error handling

A failure of `listFunctionModules` / `listFunctionGroupIncludes` (network,
non-2xx, malformed — adt-clients now throws on all of these) **propagates** and
fails the backup. A function group silently backed up without its FM/include
source would be a corrupt backup with no signal — worse than a loud failure.
This matches the "wrong-shape throws" contract just enforced in adt-clients.

If `includeCode` is false (metadata/structure-only backup), children are still
enumerated and attached (so the tree is complete), but no source is read — same
as every other node type under `includeCode: false`.

## Testing

- **Unit** (`tests/…`, mock `AdtClient`) — mirror existing tree tests:
  1. A `functionGroup` node → `listFunctionModules` returns 2 FMs and
     `listFunctionGroupIncludes` returns `[L<FUGR>TOP, L<FUGR>UXX, L<FUGR>F01]`
     → children = 2 functionModule + 2 functionInclude (TOP + F01); the
     `L<FUGR>UXX` collector is **excluded**.
  2. Pre-existing `node.children` are preserved alongside the enumerated ones.
  3. `includeCode: false` → children attached, no source read.
  4. A thrown enumeration error propagates (backup fails, not silent []).
- **Integration** (real system, shared polygon `ZAC_SHR_FUGR`) — back up the
  package and assert the tree contains `Z_AC_SHR_FM01` (functionModule, with
  source) and `LZAC_SHR_FUGRTOP` (functionInclude), and does NOT contain
  `LZAC_SHR_FUGRUXX`.
- **End-to-end** acceptance is via `cloud-llm-hub`, per the team workflow — not a
  committed cross-system test here.

## Release

`mcp-abap-adt-backup` **minor** version bump. Bump + merge + tag by the assistant;
publish by the user.

## Out of scope

- Restore of function includes (only capture now; `restoreStatus: not-implemented`).
- Backing up the generated `L<FUGR>UXX` collector and `SAPL<FUGR>` main program
  (regenerated on restore; no developer content).
