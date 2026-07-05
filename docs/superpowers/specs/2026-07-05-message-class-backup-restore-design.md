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

Helpers exported: `parseMessageClass(xml)`, `buildMessageClassXml(cls)`,
`IParsedMessage`, `IParsedMessageClass`.

Content type: `application/vnd.sap.adt.mc.messageclass+xml`.

## Key decision: message class is one atomic entity

A message class and its messages are a **single coupled unit**. We never back up or restore
individual messages as separate objects — there is no separate `SupportedType` for a message.
`getMessageClassMessage()` is purely an internal restore mechanism to set the message texts
after the shell is created.

- **Backup:** one `messageClass` tree node, one payload = the full class XML (all messages inside).
- **Restore:** create shell → upsert each message from the parsed payload.

## Payload format

`codeFormat = 'metadata-xml'`. The payload is the raw class XML from `read().readResult.data`,
consistent with other metadata-xml types (domain, package, dataElement, …).

## Backup (read)

`readMetadataXmlForType` gains a `messageClass` case:

```ts
case 'messageClass': {
  const state = await client.getMessageClass().read({ name });
  if (!state) throw new Error(`Message class ${name} not found`);
  return String(state.readResult.data); // full XML incl. <mc:messages>
}
```

The flat `--objects` path (`backupObject.ts`) gets the matching case.

## Restore

`restoreObject` gains a `messageClass` case:

1. **Shell** — `getMessageClass().create({ name, description, packageName, transportRequest })`.
   Idempotent: if the class already exists (verify → update mode), update the description via
   `getMessageClass().update(...)` instead of create.
2. **Messages** — `parseMessageClass(payloadXml)`, then for each message
   `getMessageClassMessage().update({ className: name, msgno, msgtext, selfExplanatory,
   description, transportRequest })` (upsert).
3. **No activation** — MSAG is not activatable. Distinct from the AMDP/scalar co-activation group.

The class `description` for the shell comes from the parsed payload (`parseMessageClass`), so
`buildConfigForNode` / `applyConfigName` only need name + package + transport; message texts
are re-derived from the payload at restore time, not from `config`.

## Ordering / dependencies

- `TYPE_CREATION_ORDER['messageClass']` = low (same tier as `domain` / `dataElement`), so the
  class is restored before consumers (classes/programs that reference it via `MESSAGE ID`).
- **No co-activation.** Not part of any SCC group, never bulk-activated. This is intentionally
  the opposite of the AMDP/scalar-function group — MSAG has no outgoing dependencies and is not
  activatable.
- Where-used (`usedBy`) from the existing dependency analysis picks up `consumer → messageClass`
  edges automatically; no special-casing needed.

## Verify / diff

Compare **all attributes**, at minimum the class description and every message's attributes
(`msgno`, `msgtext`, `selfExplanatory`, `description`) — not just `msgno → msgtext`.

- `verifyObjectInSystem` (`messageClass`): read the system XML, parse both sides with
  `parseMessageClass`, canonicalize (sort messages by `msgno`, stable attribute order, trim
  whitespace), and compare the full canonical form including class + message descriptions.
- `diff`: unified diff over the canonical serialization of both sides.
- Only genuinely non-deterministic server metadata (e.g. `masterSystem`, change timestamps if
  present) is excluded from the comparison; everything the user authored is compared.

## Registry threading (same pattern as scalarFunction / appendStructure)

Thread `messageClass` through every per-type registry:

- `types.ts` — add `'messageClass'` to `SupportedType`.
- `mapAdtTypeToSupported.ts` — `MSAG/N` → `messageClass`.
- `normalizeType.ts`, `typeOrder.ts`, `isRestoreImplemented.ts`, `findOtherType.ts`.
- `readPayloadForType.ts`, `readMetadataXmlForType.ts`, `backupObject.ts`.
- `restoreObject.ts`, `restoreTreeNode.ts`, `restoreObjects.ts`, `buildConfigForNode.ts`,
  `applyConfigName.ts`.
- `analyzeDependencies.ts` — `TYPE_CREATION_ORDER` entry (low), no SCC/co-activation change.
- `verifyObjectInSystem.ts` / diff path.
- Docs: `docs/roadmap.yaml`, `docs/SMOKE_CHECKLIST.md`, `CLAUDE.md`, `README.md`, `CHANGELOG.md`.
- `package.json` — bump `@mcp-abap-adt/adt-clients` to `^7.3.1`.

## Testing

- **Offline fixture:** a SchemaVersion-2 backup file with a single `messageClass` node holding
  2–3 messages → `plan` / `verify` (offline parts) / `validate` run without errors and place the
  node in an early group with no co-activation.
- **Live (with explicit permission only):** on the trial system against `ZOK_TEST` —
  backup a real message class, restore into a scratch package, verify round-trip. Per standing
  rule, ask before any authorized/live run.

## Out of scope

- Individual message objects as a standalone `SupportedType`.
- Translation/multi-language message texts beyond the master language returned by `read()`.
- Any change to the AMDP/scalar-function co-activation group.
