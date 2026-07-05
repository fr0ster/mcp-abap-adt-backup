# Message Class (MSAG) backup/restore — design

Date: 2026-07-05
Status: draft (awaiting user review)

## Goal

Migrate to `@mcp-abap-adt/adt-clients@7.3.1` (adds a message-class module) and add
backup/restore/verify support for ABAP **Message Classes** (`MSAG/N`, SE91) as a new
`SupportedType`.

## Context: the new adt-clients API (7.3.1)

`AdtClient` gains two getters:

- `getMessageClass()` → `IAdtObject<IMessageClassConfig, IMessageClassState>`
  - `objectType = 'MessageClass'`; ADT type string `MSAG/N`.
  - `create(config)` — creates only the **shell** (name / description / packageName /
    transportRequest / masterLanguage). No activation (message classes are not activatable;
    `activate`/`check`/`getVersions`/`getVersionSource` throw).
  - `read({name})` → `{ readResult, messageClass }`. `readResult.data` is the **raw class
    XML** (contains `<mc:messages>` with every message). `messageClass` is the parsed
    `IParsedMessageClass` (`name`, `description`, `language`, `messages[]`, …).
  - `update(config)` accepts only name/description/package — it does **not** carry messages.
- `getMessageClassMessage()` → `IAdtObject<IMessageClassMessageConfig, IMessageClassMessageState>`
  - `create`/`update` = **upsert** a single message (`className`, `msgno`, `msgtext`,
    `selfExplanatory?`, `description?`, `transportRequest?`) via a read-modify-write of the
    parent class XML.

Public root exports (`@mcp-abap-adt/adt-clients`): `IMessageClassConfig`,
`IMessageClassMessageConfig`, `IMessageClassState`, `IMessageClassMessageState`,
`AdtMessageClass`, `AdtMessageClassMessage`.

**Not exported from the package root:** `parseMessageClass`, `buildMessageClassXml`,
`IParsedMessage`, `IParsedMessageClass` — they live in `core/messageClass` but are not re-exported,
and deep import (`@mcp-abap-adt/adt-clients/dist/core/messageClass`) is blocked by the package
`exports` field (`ERR_PACKAGE_PATH_NOT_EXPORTED`, verified at planning time). Consequence: we
**cannot** persist raw class XML and re-parse it on restore. Instead we rely on the **already-parsed**
object that `read()` returns (`state.messageClass`), which is typed structurally in our own code (see
the local `ParsedMessageClass` shape in the plan).

Content type: `application/vnd.sap.adt.mc.messageclass+xml`.

## Key decision: message class is one backup unit

A message class and its messages are a **single coupled unit at the backup level**. We never back
up or restore individual messages as separate objects — there is no separate `SupportedType` for a
message. `getMessageClassMessage()` is purely an internal restore mechanism to set the message
texts after the shell is created.

Note this is *backup-unit* coupling, not transactional restore: restore applies the messages via
per-message read-modify-write calls (see Restore below), so it is not a single atomic operation.

- **Backup:** one `messageClass` tree node, one payload = **JSON** of the parsed class
  (`read().messageClass`: name, description, packageName, language, `messages[]`).
- **Restore:** create shell (from the parsed JSON) → upsert each message → delete target-only extras.

## Payload format

`codeFormat = 'json'` (`BackupTreeNode.codeFormat` is `'source' | 'xml' | 'json'`). The payload is
`JSON.stringify` of the parsed class returned by `read().messageClass` — a `ParsedMessageClass`
`{ name, description?, packageName?, language?, masterLanguage?, messages: ParsedMessage[] }`, where
`ParsedMessage` is `{ msgno, msgtext, selfExplanatory?, description? }`. JSON (not raw XML) because
the XML parser needed to reconstruct messages on restore is not reachable (see API note above).

## Backup (read)

`readPayloadForType` gains a dedicated `messageClass` branch (not the generic metadata branch):

```ts
case 'messageClass': {
  const state = await client.getMessageClass().read({ name });
  if (!state?.messageClass) return {};
  return { payload: JSON.stringify(state.messageClass), format: 'json' };
}
```

`readMetadataXmlForType` also gains a `messageClass` case returning the raw XML
(`state.readResult.data`) — used only by `findOtherType` type-probing and as the verify entry read;
it is **not** the restore payload. The flat `--objects` path (`backupObject.ts`) gets a matching
case that stores the JSON in `BackupObject.source` and a minimal `config` (`{ name, packageName,
description }`) derived from the parsed class.

## Restore

`restoreObject` gains a `messageClass` case:

1. **Shell** — `JSON.parse(payload)` yields the `ParsedMessageClass`. Create via
   `getMessageClass().create({ name, description, packageName, transportRequest })` using the parsed
   class's own `description`/`packageName`. Idempotent: if the class already exists (verify → update
   mode), update the description via `getMessageClass().update(...)` instead of create.
2. **Messages — full reconcile.** The parsed JSON gives the backup's message set.
   Restore must make the target class's message set *equal* to the backup, not merely merge. This
   is done as a loop of per-message read-modify-write operations (each
   `getMessageClassMessage()` call internally GET-locks-PUTs the whole class), so it is **not
   transactional** — a mid-loop failure can leave the target partially updated. Mitigation: restore
   is idempotent and re-runnable, and post-restore `verify` (full-attribute compare) detects any
   incomplete state.
   - **Upsert** every backup message via
     `getMessageClassMessage().update({ className: name, msgno, msgtext, selfExplanatory,
     description, transportRequest })`.
   - **On update mode** (class already existed — see step 1), read the current class, and for every
     message present in the target but **absent from the backup**, call
     `getMessageClassMessage().delete({ className: name, msgno, transportRequest })`. On fresh
     create there are no pre-existing messages, so no deletes are issued.
   The reconcile guarantees a completed restore leaves no stale extra messages.
3. **No activation** — MSAG is not activatable. This requires an explicit exclusion in restore
   orchestration (see *Activation exclusion* below), not just documentation.

The class `description`, `packageName`, and message texts for the shell all come from the parsed
JSON payload (`JSON.parse` → `ParsedMessageClass`), so `applyConfigName` only needs to set `name`;
nothing about the restore depends on `config` beyond that.

## Activation exclusion (required)

MSAG is not activatable, but the restore orchestrators currently emit an activation reference for
*any* restored node that has an `adtType`:

- `restoreTreeBackup.ts` `processNode` — `if (shouldActivate && node.adtType) return { name, type: node.adtType }` (line ~270); the ref then flows into `activateObjectsGroup` for `bulk`/`cluster` phases.
- `restoreObjects.ts` — pushes `{ name, type: ADT_TYPE_MAP[obj.type] }` to `activationList` for every non-package object (line ~82).

So "no activation" must be enforced in code. Introduce a small `isActivatable(type: SupportedType): boolean`
helper (returns `false` for `messageClass`) and guard both activation-ref sites with it. Also add a
`RESTORE_PHASES` entry for `messageClass` (early tier, alongside domains/data elements) so the
fallback phase path restores it; with the guard, that phase produces no activation refs.

## Ordering / dependencies

- `TYPE_CREATION_ORDER['messageClass']` = low (same tier as `domain` / `dataElement`) — this is the
  **primary** ordering driver: within the plan/fallback grouping, message classes sort ahead of
  classes/programs.
- **Source name-scan** in `buildAdjacency` is the secondary driver: a consumer's source that
  references the class by name (e.g. `MESSAGE e001(ZMSG)`) already yields a `consumer → messageClass`
  edge via the existing content scan (`analyzeDependencies.ts` lines ~40–53). No new structural-edge
  code is needed for ordering.
- **`usedBy` does not affect ordering.** `analyzeDependencyLevels()` / `buildAdjacency()` do **not**
  consume `node.usedBy`; it is informational metadata only. Adding `messageClass: 'MSAG/N'` to
  `WHERE_USED_TYPE_MAP` (in `collectTreeDependencies.ts`) is still done for parity/completeness with
  every other type, but the spec does **not** rely on it for restore ordering.
- **No co-activation.** Stays a singleton SCC, never joined into a multi-node co-activation group and
  excluded from activation refs entirely — intentionally the opposite
  of the AMDP/scalar-function group. MSAG has no outgoing dependencies and is not activatable.

## Verify / diff

Compare **all attributes**, at minimum the class description and every message's attributes
(`msgno`, `msgtext`, `selfExplanatory`, `description`) — not just `msgno → msgtext`.

- A shared helper `canonicalizeMessageClass(cls: ParsedMessageClass): string` produces a stable
  string: messages sorted by `msgno`, each rendered as its `{ msgno, msgtext, selfExplanatory,
  description }` fields in fixed order, plus the class `description`. Only user-authored fields are
  included; volatile server metadata (`masterSystem`, `responsible`, timestamps) is dropped.
- `verifyObjectInSystem` (`messageClass`): a dedicated branch reads the system via
  `getMessageClass().read()` (→ `state.messageClass`), `JSON.parse`es the backup payload, and
  compares `canonicalizeMessageClass(system)` vs `canonicalizeMessageClass(backup)` → `source-mismatch`
  on difference (after the package check).
- `diff` (`run.ts`): a dedicated `messageClass` branch (the payload is `json`, not `xml`/`source`, so
  neither existing branch fits) runs `diffUnified` over the two canonical strings.

## Registry threading (same pattern as scalarFunction / appendStructure)

Thread `messageClass` through every per-type registry:

- `types.ts` — add `'messageClass'` to `SupportedType`.
- `mapAdtTypeToSupported.ts` — `MSAG/N` → `messageClass`.
- `normalizeType.ts`, `typeOrder.ts`, `isRestoreImplemented.ts`, `findOtherType.ts`.
- `readPayloadForType.ts` (dedicated `json` branch), `readMetadataXmlForType.ts` (raw-XML case),
  `backupObject.ts` (JSON in `source`).
- `restoreObject.ts`, `restoreTreeNode.ts`, `applyConfigName.ts` (`name`). `restoreObjects.ts` needs
  **no** change — its activation guard keys on `ADT_TYPE_MAP[obj.type]`, and we deliberately do not
  add `messageClass` there, so no activation ref is emitted. `buildConfigForNode.ts` default case
  already yields `{ description, packageName, name }`; no new case needed.
- `restoreTreeBackup.ts` — add a `RESTORE_PHASES` entry for `messageClass` (early tier, `individual`)
  and guard the activation-ref emission (`processNode`, line ~270) with `isActivatable(node.type)`.
- New `isActivatable(type)` helper in `restore/` — returns `false` for `messageClass`, `true`
  otherwise; used at the `restoreTreeBackup.processNode` activation-ref site.
- New `canonicalizeMessageClass` + a local `ParsedMessageClass`/`ParsedMessage` type (e.g. in
  `xml/` or `verify/`), used by verify and diff.
- `analyzeDependencies.ts` — `TYPE_CREATION_ORDER` entry (low), no SCC/co-activation change.
- `dependencies/collectTreeDependencies.ts` — add `messageClass: 'MSAG/N'` to `WHERE_USED_TYPE_MAP`
  (parity only; does not drive ordering).
- `verifyObjectInSystem.ts` (dedicated branch) and `run.ts` diff (dedicated branch).
- Docs: `docs/roadmap.yaml`, `docs/SMOKE_CHECKLIST.md`, `CLAUDE.md`, `README.md`, `CHANGELOG.md`.
- `package.json` — bump `@mcp-abap-adt/adt-clients` to `^7.3.1`.

## Testing

- **Offline fixture:** a SchemaVersion-2 backup file with a single `messageClass` node holding
  2–3 messages → `plan` / `validate` (both offline) run without errors and place the node in an
  early group with no co-activation. (`verify` is online and is exercised in the live step below,
  not offline.)
- **Live (with explicit permission only):** on the trial system against `ZOK_TEST` — backup a real
  message class, restore into a scratch package, then run `verify` and confirm the round-trip
  (including the reconcile: a target message absent from the backup is deleted). Per standing rule,
  ask before any authorized/live run.

## Out of scope

- Individual message objects as a standalone `SupportedType`.
- Translation/multi-language message texts beyond the master language returned by `read()`.
- Any change to the AMDP/scalar-function co-activation group.
