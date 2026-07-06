# Message Class (MSAG) Backup/Restore Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add backup/restore/verify/diff support for ABAP Message Classes (`MSAG/N`, SE91) as a new `SupportedType`, on `@mcp-abap-adt/adt-clients@7.3.1`.

**Architecture:** A message class + its messages are one backup unit. Payload is JSON of the parsed class (`getMessageClass().read().messageClass`), because the XML parser needed to reconstruct messages on restore is not reachable from the package root. Restore creates the class shell, upserts each message via `getMessageClassMessage()`, and (in update mode) deletes target messages absent from the backup. Message classes are not activatable and are excluded from all activation refs. Ordering comes from a low `TYPE_CREATION_ORDER` plus the existing source name-scan.

**Tech Stack:** TypeScript (strict, CommonJS, es2022), `@mcp-abap-adt/adt-clients`, `yaml`, `fast-xml-parser`, Biome. Node.js >= 22.

## Global Constraints

- Node.js >= 22 (`engines.node: ">=22.0.0"`). CI/release build on Node 22.
- `@mcp-abap-adt/adt-clients` pinned to `^7.3.1`.
- Biome: 2-space indent, single quotes, semicolons; `organizeImports: on`. Run `npm run lint` before each commit.
- TypeScript strict; `noExplicitAny`: warn in production (avoid `any` in new code).
- All code artifacts in English. Commit summaries imperative, <= 72 chars, scope where useful.
- No automated unit-test framework exists. Offline tests are plain Node scripts under `tests/offline/*.cjs` that `require()` compiled modules from `dist/`, run via `npm run test:offline` after `npm run build:fast`. They must exit non-zero on failure.
- **Do not** run any SAP-authorized/live command (`backup`, `verify`, `check`, `restore`, `diff` online) without explicit user permission each time (trial needs browser-profile activation). Task 8 is gated on this.
- `parseMessageClass` / `buildMessageClassXml` / `IParsedMessage` / `IParsedMessageClass` are **not** importable (root export missing; deep import blocked by `exports`). Use the parsed object from `read().messageClass` and a local `ParsedMessageClass` type instead.

**adt-clients API facts (verified):**
- `client.getMessageClass()` → `IAdtObject<IMessageClassConfig, IMessageClassState>`.
  - `create(config)` / `update(config)` where `IMessageClassConfig = { name, description?, packageName?, transportRequest?, masterLanguage? }`.
  - `read({ name })` → `IMessageClassState | undefined`; `state.readResult.data` is raw XML, `state.messageClass` is the parsed class `{ name, description?, packageName?, language?, masterLanguage?, messages: Array<{ msgno, msgtext, selfExplanatory?, description? }> }`.
- `client.getMessageClassMessage()` → `IAdtObject<IMessageClassMessageConfig, IMessageClassMessageState>`.
  - `update(config)` upserts one message; `delete(config)` removes one message. `IMessageClassMessageConfig = { className, msgno, msgtext?, selfExplanatory?, description?, transportRequest? }`.
- ADT type string: `MSAG/N`.

---

## File Structure

New files:
- `src/lib/messageClass/types.ts` — `ParsedMessageClass`, `ParsedMessage` (local structural types for JSON payloads).
- `src/lib/messageClass/canonicalizeMessageClass.ts` — stable string form for verify/diff.
- `src/lib/messageClass/restoreMessageClass.ts` — shared shell+upsert+reconcile helper.
- `src/lib/restore/isActivatable.ts` — activation gate.
- `tests/fixtures/messageclass.backup.yaml` — offline plan/validate fixture.
- `tests/offline/messageclass.cjs` — offline assertions.

Modified files (one responsibility each, existing per-type registries):
- `package.json` — `test:offline` script (+ confirm adt-clients `^7.3.1`).
- `src/lib/types.ts`, `src/lib/utils/normalizeType.ts`, `src/lib/constants/typeOrder.ts`, `src/lib/tree/isRestoreImplemented.ts`, `src/lib/tree/mapAdtTypeToSupported.ts`, `src/lib/verify/findOtherType.ts`, `src/lib/utils/applyConfigName.ts`.
- `src/lib/backup/readMetadataXmlForType.ts`, `src/lib/tree/readPayloadForType.ts`, `src/lib/backup/backupObject.ts`.
- `src/lib/restore/restoreObject.ts`, `src/lib/restore/restoreTreeNode.ts`, `src/lib/restore/restoreTreeBackup.ts`.
- `src/lib/restore/analyzeDependencies.ts`, `src/lib/dependencies/collectTreeDependencies.ts`.
- `src/lib/verify/verifyObjectInSystem.ts`, `src/lib/run.ts` (diff branch).
- `docs/roadmap.yaml`, `docs/SMOKE_CHECKLIST.md`, `CLAUDE.md`, `README.md`, `CHANGELOG.md`.

---

## Task 1: New type + trivial registries + offline test harness

**Files:**
- Modify: `package.json` (scripts)
- Modify: `src/lib/types.ts` (SupportedType union)
- Modify: `src/lib/utils/normalizeType.ts`
- Modify: `src/lib/constants/typeOrder.ts`
- Modify: `src/lib/tree/isRestoreImplemented.ts`
- Modify: `src/lib/tree/mapAdtTypeToSupported.ts`
- Modify: `src/lib/verify/findOtherType.ts`
- Modify: `src/lib/utils/applyConfigName.ts`
- Test: `tests/offline/messageclass.cjs`

**Interfaces:**
- Produces: `SupportedType` includes `'messageClass'`; `mapAdtTypeToSupported('MSAG/N') === 'messageClass'`; `normalizeType('messageClass') === 'messageClass'`; `isRestoreImplemented('messageClass') === true`; `applyConfigName('messageClass', name, ...)` sets `config.name = name`.
- Produces: `npm run test:offline` runs `tests/offline/*.cjs`.

- [ ] **Step 1: Add the `test:offline` npm script**

In `package.json` `scripts`, add after `"test:integration"`:

```json
    "test:offline": "node tests/offline/messageclass.cjs",
```

Also confirm `"@mcp-abap-adt/adt-clients": "^7.3.1"` in `dependencies` (already bumped; if not, set it and run `npm install`).

- [ ] **Step 2: Write the failing test**

Create `tests/offline/messageclass.cjs`:

```js
'use strict';
// Offline assertions for message-class support. Runs against compiled dist/.
const assert = require('node:assert');

const { mapAdtTypeToSupported } = require('../../dist/lib/tree/mapAdtTypeToSupported');
const { normalizeType } = require('../../dist/lib/utils/normalizeType');
const { isRestoreImplemented } = require('../../dist/lib/tree/isRestoreImplemented');
const { applyConfigName } = require('../../dist/lib/utils/applyConfigName');

// --- Task 1: type + registries ---
assert.strictEqual(mapAdtTypeToSupported('MSAG/N'), 'messageClass', 'MSAG/N maps to messageClass');
assert.strictEqual(normalizeType('messageClass'), 'messageClass', 'normalizeType passes messageClass');
assert.strictEqual(normalizeType('message_class'), 'messageClass', 'normalizeType snake_case');
assert.strictEqual(isRestoreImplemented('messageClass'), true, 'messageClass restore implemented');
assert.strictEqual(
  applyConfigName('messageClass', 'ZMY_MSG').name,
  'ZMY_MSG',
  'applyConfigName sets .name for messageClass',
);

console.log('OK task1');
```

- [ ] **Step 3: Run test to verify it fails**

Run: `npm run build:fast && npm run test:offline`
Expected: build fails, or test throws — `'messageClass'` is not yet a `SupportedType` (TS error) / `mapAdtTypeToSupported('MSAG/N')` returns `undefined`.

- [ ] **Step 4: Add `messageClass` to the union**

In `src/lib/types.ts`, add to the `SupportedType` union (after `'appendStructure'`):

```ts
  | 'appendStructure'
  | 'messageClass'
  | 'unitTest'
```

- [ ] **Step 5: Map the ADT type**

In `src/lib/tree/mapAdtTypeToSupported.ts`, add to the exact-match `map` (after `'DCLS/DL': 'accessControl',`):

```ts
    'DCLS/DL': 'accessControl',
    'MSAG/N': 'messageClass',
```

And add a prefix rule near the other prefix rules (after the `DCLS/` rule):

```ts
  if (normalized.startsWith('DCLS/')) return 'accessControl';
  if (normalized.startsWith('MSAG/')) return 'messageClass';
```

- [ ] **Step 6: Normalize + order + restore-implemented + config name**

In `src/lib/utils/normalizeType.ts`, add to `map` (after the `enhancement` entries or anywhere in the object):

```ts
    messageclass: 'messageClass',
    message_class: 'messageClass',
```

In `src/lib/constants/typeOrder.ts`, add `'messageClass'` early (right after `'dataElement'`):

```ts
  'dataElement',
  'messageClass',
  'structure',
```

In `src/lib/tree/isRestoreImplemented.ts`, add a case (with the other `case` labels before `return true;`):

```ts
    case 'appendStructure':
    case 'messageClass':
      return true;
```

In `src/lib/verify/findOtherType.ts`, add `'messageClass'` to the `supportedTypes` array (after `'appendStructure'`):

```ts
  'appendStructure',
  'messageClass',
```

In `src/lib/utils/applyConfigName.ts`, add a case (after the `appendStructure` case):

```ts
    case 'appendStructure':
      finalConfig.appendStructureName = name;
      break;
    case 'messageClass':
      finalConfig.name = name;
      break;
```

- [ ] **Step 7: Run test to verify it passes**

Run: `npm run build:fast && npm run test:offline`
Expected: `OK task1`

- [ ] **Step 8: Lint + commit**

```bash
npm run lint
git add package.json src/lib/types.ts src/lib/utils/normalizeType.ts src/lib/constants/typeOrder.ts src/lib/tree/isRestoreImplemented.ts src/lib/tree/mapAdtTypeToSupported.ts src/lib/verify/findOtherType.ts src/lib/utils/applyConfigName.ts tests/offline/messageclass.cjs
git commit -m "feat(msag): add messageClass type + registries"
```

---

## Task 2: Backup read path (JSON payload)

**Files:**
- Modify: `src/lib/backup/readMetadataXmlForType.ts`
- Modify: `src/lib/tree/readPayloadForType.ts`
- Modify: `src/lib/backup/backupObject.ts`
- Test: `tests/offline/messageclass.cjs`

**Interfaces:**
- Consumes: `client.getMessageClass().read({ name })` → `{ readResult, messageClass }`.
- Produces: `readPayloadForType(client, 'messageClass', name)` resolves `{ payload: <json>, format: 'json' }`; `readMetadataXmlForType(client, 'messageClass', name)` resolves the raw XML string; `backupObject(client, { type:'messageClass', name })` returns `{ id, type, name, config:{name,packageName,description}, source: <json> }`.

- [ ] **Step 1: Add failing test (append to `tests/offline/messageclass.cjs`)**

Before `console.log('OK task1');`, insert a block. It builds a fake client and checks the read path:

```js
// --- Task 2: backup read path ---
const { readPayloadForType } = require('../../dist/lib/tree/readPayloadForType');
const { readMetadataXmlForType } = require('../../dist/lib/backup/readMetadataXmlForType');
const { backupObject } = require('../../dist/lib/backup/backupObject');

function fakeReadClient() {
  const parsed = {
    name: 'ZMY_MSG',
    description: 'My messages',
    packageName: 'ZPKG',
    language: 'E',
    messages: [
      { msgno: '001', msgtext: 'First', selfExplanatory: false },
      { msgno: '002', msgtext: 'Second', selfExplanatory: true, description: 'why' },
    ],
  };
  return {
    getMessageClass() {
      return {
        async read() {
          return { readResult: { data: '<mc:messageClass/>' }, messageClass: parsed, errors: [] };
        },
      };
    },
  };
}

(async () => {
  const client = fakeReadClient();
  const payload = await readPayloadForType(client, 'messageClass', 'ZMY_MSG');
  assert.strictEqual(payload.format, 'json', 'payload format json');
  const roundtrip = JSON.parse(payload.payload);
  assert.strictEqual(roundtrip.messages.length, 2, 'payload has 2 messages');
  assert.strictEqual(roundtrip.name, 'ZMY_MSG', 'payload has class name');

  const xml = await readMetadataXmlForType(client, 'messageClass', 'ZMY_MSG');
  assert.strictEqual(xml, '<mc:messageClass/>', 'metadata returns raw xml');

  const obj = await backupObject(client, { type: 'messageClass', name: 'ZMY_MSG' });
  assert.strictEqual(obj.config.packageName, 'ZPKG', 'flat backup config packageName');
  assert.strictEqual(JSON.parse(obj.source).messages.length, 2, 'flat backup source json');

  console.log('OK task2');
})().catch((e) => { console.error(e); process.exit(1); });
```

Then move `console.log('OK task1');` to just before this async block (task1 assertions stay synchronous at the top).

- [ ] **Step 2: Run test to verify it fails**

Run: `npm run build:fast && npm run test:offline`
Expected: FAIL — `readPayloadForType` returns `{}` for `messageClass` (no `format`), assertion throws.

- [ ] **Step 3: Add the `messageClass` case to `readMetadataXmlForType`**

In `src/lib/backup/readMetadataXmlForType.ts`, add a case before `default:`:

```ts
      case 'messageClass': {
        const state = await client.getMessageClass().read({ name });
        result = state?.readResult?.data as string | undefined;
        break;
      }
```

- [ ] **Step 4: Add the dedicated `messageClass` branch to `readPayloadForType`**

In `src/lib/tree/readPayloadForType.ts`, add a case before the metadata (`domain`/`dataElement`/…) group:

```ts
    case 'messageClass': {
      const state = await client.getMessageClass().read({ name });
      if (!state?.messageClass) {
        return {};
      }
      return { payload: JSON.stringify(state.messageClass), format: 'json' };
    }
```

- [ ] **Step 5: Add the `messageClass` case to `backupObject`**

In `src/lib/backup/backupObject.ts`, add a case before `default:` (uses the parsed class for both config and source):

```ts
    case 'messageClass': {
      const state = await client.getMessageClass().read({ name: spec.name });
      if (!state?.messageClass) {
        throw new Error(`Message class not found: ${spec.name}`);
      }
      const mc = state.messageClass;
      const config = applyConfigName(spec.type, spec.name, spec.functionGroupName, {
        name: spec.name,
        packageName: mc.packageName,
        description: mc.description,
      } as BackupConfig);
      return {
        id,
        type: spec.type,
        name: spec.name,
        config,
        source: JSON.stringify(mc),
      };
    }
```

- [ ] **Step 6: Run test to verify it passes**

Run: `npm run build:fast && npm run test:offline`
Expected: `OK task2`

- [ ] **Step 7: Lint + commit**

```bash
npm run lint
git add src/lib/backup/readMetadataXmlForType.ts src/lib/tree/readPayloadForType.ts src/lib/backup/backupObject.ts tests/offline/messageclass.cjs
git commit -m "feat(msag): backup reads parsed class as json payload"
```

---

## Task 3: Restore helper + activation gate

**Files:**
- Create: `src/lib/messageClass/types.ts`
- Create: `src/lib/messageClass/restoreMessageClass.ts`
- Create: `src/lib/restore/isActivatable.ts`
- Test: `tests/offline/messageclass.cjs`

**Interfaces:**
- Produces: `type ParsedMessage = { msgno: string; msgtext: string; selfExplanatory?: boolean; description?: string }` and `type ParsedMessageClass = { name: string; description?: string; packageName?: string; language?: string; masterLanguage?: string; messages: ParsedMessage[] }`.
- Produces: `restoreMessageClass(client, parsed: ParsedMessageClass, opts: { mode: RestoreMode; name: string; description?: string; packageName?: string; transportRequest?: string }): Promise<void>` — create/update shell, upsert every message, and in update mode delete target messages absent from `parsed`.
- Produces: `isActivatable(type?: SupportedType): boolean` — `false` for `messageClass`, else `true`.

- [ ] **Step 1: Add failing test (append inside the async block in `tests/offline/messageclass.cjs`, before `console.log('OK task2')` → change to a task3 log)**

Add after the task2 assertions, still inside the async IIFE:

```js
  // --- Task 3: restore helper + activation gate ---
  const { restoreMessageClass } = require('../../dist/lib/messageClass/restoreMessageClass');
  const { isActivatable } = require('../../dist/lib/restore/isActivatable');

  assert.strictEqual(isActivatable('messageClass'), false, 'messageClass not activatable');
  assert.strictEqual(isActivatable('class'), true, 'class activatable');

  function fakeRestoreClient(existingMsgnos) {
    const calls = { create: 0, update: 0, msgUpsert: [], msgDelete: [] };
    return {
      calls,
      getMessageClass() {
        return {
          async create() { calls.create++; },
          async update() { calls.update++; },
          async read() {
            return { messageClass: { messages: existingMsgnos.map((n) => ({ msgno: n, msgtext: 'x' })) } };
          },
        };
      },
      getMessageClassMessage() {
        return {
          async update(cfg) { calls.msgUpsert.push(cfg.msgno); },
          async delete(cfg) { calls.msgDelete.push(cfg.msgno); },
        };
      },
    };
  }

  const parsed = { name: 'ZMY_MSG', description: 'd', packageName: 'ZPKG',
    messages: [{ msgno: '001', msgtext: 'a' }, { msgno: '002', msgtext: 'b' }] };

  // create mode: shell created, both messages upserted, nothing deleted
  const c1 = fakeRestoreClient([]);
  await restoreMessageClass(c1, parsed, { mode: 'create', name: 'ZMY_MSG', description: 'd', packageName: 'ZPKG' });
  assert.strictEqual(c1.calls.create, 1, 'create shell once');
  assert.deepStrictEqual(c1.calls.msgUpsert.sort(), ['001', '002'], 'upsert both');
  assert.deepStrictEqual(c1.calls.msgDelete, [], 'no deletes on create');

  // update mode: target has extra '003' -> it must be deleted
  const c2 = fakeRestoreClient(['001', '002', '003']);
  await restoreMessageClass(c2, parsed, { mode: 'update', name: 'ZMY_MSG', description: 'd', packageName: 'ZPKG' });
  assert.strictEqual(c2.calls.update, 1, 'update shell once');
  assert.deepStrictEqual(c2.calls.msgUpsert.sort(), ['001', '002'], 'upsert both on update');
  assert.deepStrictEqual(c2.calls.msgDelete, ['003'], 'delete target-only extra');
```

Change the final log to `console.log('OK task3');` (replacing `OK task2`).

- [ ] **Step 2: Run test to verify it fails**

Run: `npm run build:fast && npm run test:offline`
Expected: FAIL — `Cannot find module '.../restoreMessageClass'`.

- [ ] **Step 3: Create the local types**

Create `src/lib/messageClass/types.ts`:

```ts
// Local structural types for message-class JSON payloads. The adt-clients
// IParsedMessage / IParsedMessageClass are not exported from the package root,
// so we mirror the shape we depend on here.
export interface ParsedMessage {
  msgno: string;
  msgtext: string;
  selfExplanatory?: boolean;
  description?: string;
}

export interface ParsedMessageClass {
  name: string;
  description?: string;
  packageName?: string;
  language?: string;
  masterLanguage?: string;
  messages: ParsedMessage[];
}
```

- [ ] **Step 4: Create the activation gate**

Create `src/lib/restore/isActivatable.ts`:

```ts
import type { SupportedType } from '../types';

// Message classes (MSAG) are not activatable — they must never be sent to
// activateObjectsGroup. Everything else follows the normal activate-on-create
// / bulk-activate flow.
const NON_ACTIVATABLE: ReadonlySet<SupportedType> = new Set(['messageClass']);

export function isActivatable(type?: SupportedType): boolean {
  return type ? !NON_ACTIVATABLE.has(type) : true;
}
```

- [ ] **Step 5: Create the restore helper**

Create `src/lib/messageClass/restoreMessageClass.ts`:

```ts
import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import type { RestoreMode } from '../types';
import type { ParsedMessageClass } from './types';

export interface RestoreMessageClassOptions {
  mode: RestoreMode;
  name: string;
  description?: string;
  packageName?: string;
  transportRequest?: string;
}

/**
 * Restore a message class as one unit: create/update the shell, upsert every
 * message from the backup, and (update mode only) delete target messages that
 * are absent from the backup so the target's message set equals the backup.
 *
 * Not transactional — each getMessageClassMessage() call GET-locks-PUTs the
 * whole class. Idempotent and safe to re-run.
 */
export async function restoreMessageClass(
  client: AdtClient,
  parsed: ParsedMessageClass,
  opts: RestoreMessageClassOptions,
): Promise<void> {
  const { mode, name, description, packageName, transportRequest } = opts;
  const mc = client.getMessageClass();
  const mcm = client.getMessageClassMessage();

  if (mode === 'create') {
    await mc.create({ name, description, packageName, transportRequest });
  } else {
    // update (or upsert already resolved): sync the shell description
    await mc.update({ name, description });
  }

  for (const msg of parsed.messages) {
    await mcm.update({
      className: name,
      msgno: msg.msgno,
      msgtext: msg.msgtext,
      selfExplanatory: msg.selfExplanatory,
      description: msg.description,
      transportRequest,
    });
  }

  if (mode !== 'create') {
    const current = await mc.read({ name });
    const keep = new Set(parsed.messages.map((m) => m.msgno));
    const existing = current?.messageClass?.messages ?? [];
    for (const cm of existing) {
      if (!keep.has(cm.msgno)) {
        await mcm.delete({ className: name, msgno: cm.msgno, transportRequest });
      }
    }
  }
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `npm run build:fast && npm run test:offline`
Expected: `OK task3`

- [ ] **Step 7: Lint + commit**

```bash
npm run lint
git add src/lib/messageClass/types.ts src/lib/messageClass/restoreMessageClass.ts src/lib/restore/isActivatable.ts tests/offline/messageclass.cjs
git commit -m "feat(msag): add restore helper (upsert+reconcile) and activation gate"
```

---

## Task 4: Wire restore into both restore paths + phase + activation guard

**Files:**
- Modify: `src/lib/restore/restoreObject.ts`
- Modify: `src/lib/restore/restoreTreeNode.ts`
- Modify: `src/lib/restore/restoreTreeBackup.ts`
- Test: `tests/offline/messageclass.cjs`

**Interfaces:**
- Consumes: `restoreMessageClass`, `ParsedMessageClass`, `isActivatable`.
- Produces: `restoreObject`/`restoreTreeNode` handle `messageClass` by parsing the JSON payload and delegating to `restoreMessageClass`; `RESTORE_PHASES` has an early `Message Classes` phase; `processNode` emits no activation ref for non-activatable types.

- [ ] **Step 1: Add failing test (append inside the async IIFE, before the final log)**

```js
  // --- Task 4: restoreObject / restoreTreeNode delegate to helper ---
  const { restoreObject } = require('../../dist/lib/restore/restoreObject');
  const { restoreTreeNode } = require('../../dist/lib/restore/restoreTreeNode');

  const objClient = fakeRestoreClient([]);
  await restoreObject(objClient, {
    id: 'MESSAGECLASS:ZMY_MSG', type: 'messageClass', name: 'ZMY_MSG',
    config: { name: 'ZMY_MSG' }, source: JSON.stringify(parsed),
  }, 'create', false);
  assert.strictEqual(objClient.calls.create, 1, 'restoreObject creates shell');
  assert.deepStrictEqual(objClient.calls.msgUpsert.sort(), ['001', '002'], 'restoreObject upserts messages');

  const treeClient = fakeRestoreClient([]);
  const codeBase64 = Buffer.from(JSON.stringify(parsed), 'utf8').toString('base64');
  await restoreTreeNode(treeClient, {
    type: 'messageClass', name: 'ZMY_MSG', restoreStatus: 'ok',
    codeFormat: 'json', codeBase64, config: { name: 'ZMY_MSG' },
  }, 'create', false);
  assert.strictEqual(treeClient.calls.create, 1, 'restoreTreeNode creates shell');
  assert.deepStrictEqual(treeClient.calls.msgUpsert.sort(), ['001', '002'], 'restoreTreeNode upserts messages');
```

Keep the final `console.log('OK task3');` → change to `console.log('OK task4');`.

- [ ] **Step 2: Run test to verify it fails**

Run: `npm run build:fast && npm run test:offline`
Expected: FAIL — `restoreObject` has no `messageClass` case; `objClient.calls.create` stays 0.

- [ ] **Step 3: Add the `messageClass` case to `restoreObject`**

In `src/lib/restore/restoreObject.ts`, add the import at the top (with the other local imports):

```ts
import { restoreMessageClass } from '../messageClass/restoreMessageClass';
import type { ParsedMessageClass } from '../messageClass/types';
```

Add a case before the closing `}` of the `switch` (after `appendStructure`):

```ts
    case 'messageClass': {
      if (!obj.source) {
        throw new Error(`messageClass ${obj.name}: missing payload (cannot restore)`);
      }
      const parsed = JSON.parse(obj.source) as ParsedMessageClass;
      await restoreMessageClass(client, parsed, {
        mode,
        name: obj.name,
        description: parsed.description ?? (config.description as string | undefined),
        packageName: parsed.packageName ?? (config.packageName as string | undefined),
        transportRequest,
      });
      return;
    }
```

- [ ] **Step 4: Add the `messageClass` case to `restoreTreeNode`**

In `src/lib/restore/restoreTreeNode.ts`, add the imports (with the other local imports):

```ts
import { restoreMessageClass } from '../messageClass/restoreMessageClass';
import type { ParsedMessageClass } from '../messageClass/types';
```

Add a case before the closing `}` of the `switch` (after `appendStructure`). `payload` (decoded `codeBase64`) is the JSON string:

```ts
      case 'messageClass': {
        if (!payload) {
          return;
        }
        const parsed = JSON.parse(payload) as ParsedMessageClass;
        await restoreMessageClass(client, parsed, {
          mode,
          name: node.name,
          description: parsed.description ?? node.description,
          packageName:
            parsed.packageName ?? (config.packageName as string | undefined),
          transportRequest,
        });
        return;
      }
```

- [ ] **Step 5: Add the phase + guard the activation ref in `restoreTreeBackup`**

In `src/lib/restore/restoreTreeBackup.ts`, add the import near the top:

```ts
import { isActivatable } from './isActivatable';
```

Add a `RESTORE_PHASES` entry early — right after the `Data Elements` entry:

```ts
  { name: 'Data Elements', types: ['dataElement'], activation: 'individual' },
  { name: 'Message Classes', types: ['messageClass'], activation: 'individual' },
  { name: 'Structures', types: ['structure'], activation: 'individual' },
```

Guard the activation-ref emission in `processNode` (the `if (shouldActivate && node.adtType)` line):

```ts
      if (shouldActivate && node.adtType && isActivatable(node.type)) {
        return { name: node.name, type: node.adtType };
      }
```

(`restoreObjects.ts` needs no change: its activation guard keys on `ADT_TYPE_MAP[obj.type]`, and `messageClass` is deliberately absent from that map.)

- [ ] **Step 6: Run test to verify it passes**

Run: `npm run build:fast && npm run test:offline`
Expected: `OK task4`

- [ ] **Step 7: Lint + commit**

```bash
npm run lint
git add src/lib/restore/restoreObject.ts src/lib/restore/restoreTreeNode.ts src/lib/restore/restoreTreeBackup.ts tests/offline/messageclass.cjs
git commit -m "feat(msag): wire restore paths, add phase, exclude from activation"
```

---

## Task 5: Ordering (creation order + where-used) + plan fixture

**Files:**
- Modify: `src/lib/restore/analyzeDependencies.ts` (`TYPE_CREATION_ORDER`)
- Modify: `src/lib/dependencies/collectTreeDependencies.ts` (`WHERE_USED_TYPE_MAP`)
- Create: `tests/fixtures/messageclass.backup.yaml`
- Test: CLI `plan` + `validate` (offline)

**Interfaces:**
- Produces: message-class node sorts into an earlier restore group than a class that references it, and never clusters/co-activates.

- [ ] **Step 1: Add the creation-order + where-used entries**

In `src/lib/restore/analyzeDependencies.ts`, add to `TYPE_CREATION_ORDER` (low tier, next to `dataElement`):

```ts
  domain: 0,
  dataElement: 1,
  messageClass: 1,
  structure: 2,
```

In `src/lib/dependencies/collectTreeDependencies.ts`, add to `WHERE_USED_TYPE_MAP` (after `dataElement`):

```ts
  dataElement: 'DTEL/DE',
  messageClass: 'MSAG/N',
  structure: 'STRU/DT',
```

- [ ] **Step 2: Create the offline fixture**

Create `tests/fixtures/messageclass.backup.yaml`. The class source references the message class name `ZMY_MSG` so the source name-scan yields a `class → messageClass` edge:

```yaml
schemaVersion: 2
package: ZTEST_MSAG
root:
  type: package
  name: ZTEST_MSAG
  restoreStatus: ok
  children:
    - type: messageClass
      name: ZMY_MSG
      restoreStatus: ok
      codeFormat: json
      config:
        name: ZMY_MSG
      # {"name":"ZMY_MSG","description":"My messages","packageName":"ZTEST_MSAG","messages":[{"msgno":"001","msgtext":"First"},{"msgno":"002","msgtext":"Second","selfExplanatory":true}]}
      codeBase64: eyJuYW1lIjoiWk1ZX01TRyIsImRlc2NyaXB0aW9uIjoiTXkgbWVzc2FnZXMiLCJwYWNrYWdlTmFtZSI6IlpURVNUX01TQUciLCJtZXNzYWdlcyI6W3sibXNnbm8iOiIwMDEiLCJtc2d0ZXh0IjoiRmlyc3QifSx7Im1zZ25vIjoiMDAyIiwibXNndGV4dCI6IlNlY29uZCIsInNlbGZFeHBsYW5hdG9yeSI6dHJ1ZX1dfQ==
    - type: class
      name: ZCL_USES_MSG
      restoreStatus: ok
      codeFormat: source
      # "CLASS zcl_uses_msg DEFINITION. METHOD m. MESSAGE e001(ZMY_MSG). ENDCLASS."
      codeBase64: Q0xBU1MgemNsX3VzZXNfbXNnIERFRklOSVRJT04uIE1FVEhPRCBtLiBNRVNTQUdFIGUwMDEoWk1ZX01TRykuIEVORENMQVNTLg==
```

> Note: the `codeBase64` for the message-class node must decode to the JSON in the comment above it. In Step 3 you will regenerate both base64 values with `base64` to guarantee correctness rather than trusting the literals here.

- [ ] **Step 3: Regenerate the fixture base64 deterministically**

Run these and paste the outputs into the fixture (replaces any transcription error in Step 2):

```bash
printf '%s' '{"name":"ZMY_MSG","description":"My messages","packageName":"ZTEST_MSAG","messages":[{"msgno":"001","msgtext":"First"},{"msgno":"002","msgtext":"Second","selfExplanatory":true}]}' | base64 -w0
printf '%s' 'CLASS zcl_uses_msg DEFINITION. METHOD m. MESSAGE e001(ZMY_MSG). ENDCLASS.' | base64 -w0
```

Set the message-class node's `codeBase64` to the first output and the class node's `codeBase64` to the second.

- [ ] **Step 4: Build, then run `plan` (offline) and inspect grouping**

```bash
npm run build:fast
node dist/bin/adt-backup.js plan --input tests/fixtures/messageclass.backup.yaml --output /tmp/msag-plan.yaml
cat /tmp/msag-plan.yaml
```

Expected: `ZMY_MSG` (messageClass) appears in a group with a **lower** `id` than the group containing `ZCL_USES_MSG` (class), and the messageClass action's group is not marked `isCircular: true`. Confirm `MESSAGECLASS:ZMY_MSG` and `CLASS:ZCL_USES_MSG` are in **different** groups, message class first.

> If the CLI flag names differ, check usage with `node dist/bin/adt-backup.js plan --help` (the command is offline; it only reads the backup file). Use the flags it prints.

- [ ] **Step 5: Run `validate` (offline) to confirm the fixture parses cleanly**

```bash
node dist/bin/adt-backup.js validate --input tests/fixtures/messageclass.backup.yaml
```

Expected: `Backup validated`.

- [ ] **Step 6: Commit**

```bash
npm run lint
git add src/lib/restore/analyzeDependencies.ts src/lib/dependencies/collectTreeDependencies.ts tests/fixtures/messageclass.backup.yaml
git commit -m "feat(msag): order message classes early; add plan fixture"
```

---

## Task 6: Verify + diff (full-attribute compare)

**Files:**
- Create: `src/lib/messageClass/canonicalizeMessageClass.ts`
- Modify: `src/lib/verify/verifyObjectInSystem.ts`
- Modify: `src/lib/run.ts` (diff branch)
- Test: `tests/offline/messageclass.cjs`

**Interfaces:**
- Consumes: `ParsedMessageClass`.
- Produces: `canonicalizeMessageClass(cls: ParsedMessageClass): string` — messages sorted by `msgno`, each line `msgno|msgtext|selfExplanatory|description`, prefixed by a class-description line; only user-authored fields.
- Produces: `verifyObjectInSystem` returns `source-mismatch` when the system message set differs from the backup; `diff` prints a unified diff over the two canonical strings.

- [ ] **Step 1: Add failing test (append inside the async IIFE, before the final log)**

```js
  // --- Task 6: canonicalization ---
  const { canonicalizeMessageClass } = require('../../dist/lib/messageClass/canonicalizeMessageClass');
  const a = canonicalizeMessageClass({ name: 'Z', description: 'd',
    messages: [{ msgno: '002', msgtext: 'b' }, { msgno: '001', msgtext: 'a' }] });
  const b = canonicalizeMessageClass({ name: 'Z', description: 'd',
    messages: [{ msgno: '001', msgtext: 'a' }, { msgno: '002', msgtext: 'b' }] });
  assert.strictEqual(a, b, 'canonical form is order-independent');
  const c = canonicalizeMessageClass({ name: 'Z', description: 'd',
    messages: [{ msgno: '001', msgtext: 'CHANGED' }, { msgno: '002', msgtext: 'b' }] });
  assert.notStrictEqual(a, c, 'canonical form reflects msgtext changes');
  const d = canonicalizeMessageClass({ name: 'Z', description: 'DIFFERENT',
    messages: [{ msgno: '001', msgtext: 'a' }, { msgno: '002', msgtext: 'b' }] });
  assert.notStrictEqual(a, d, 'canonical form reflects class description changes');
```

Change the final log to `console.log('OK task6');`.

- [ ] **Step 2: Run test to verify it fails**

Run: `npm run build:fast && npm run test:offline`
Expected: FAIL — module `canonicalizeMessageClass` not found.

- [ ] **Step 3: Create the canonicalizer**

Create `src/lib/messageClass/canonicalizeMessageClass.ts`:

```ts
import type { ParsedMessageClass } from './types';

/**
 * Stable, comparable string form of a message class. Messages are sorted by
 * msgno; only user-authored fields are included (class description + each
 * message's msgno/msgtext/selfExplanatory/description). Volatile server
 * metadata (masterSystem, responsible, timestamps) is intentionally excluded.
 */
export function canonicalizeMessageClass(cls: ParsedMessageClass): string {
  const lines: string[] = [`class|${cls.description ?? ''}`];
  const messages = [...(cls.messages ?? [])].sort((a, b) =>
    a.msgno.localeCompare(b.msgno),
  );
  for (const m of messages) {
    lines.push(
      `${m.msgno}|${m.msgtext ?? ''}|${m.selfExplanatory ? '1' : '0'}|${m.description ?? ''}`,
    );
  }
  return lines.join('\n');
}
```

- [ ] **Step 4: Add the `messageClass` branch to `verifyObjectInSystem`**

In `src/lib/verify/verifyObjectInSystem.ts`, add imports:

```ts
import { canonicalizeMessageClass } from '../messageClass/canonicalizeMessageClass';
import type { ParsedMessageClass } from '../messageClass/types';
```

Insert a dedicated branch at the very start of the `try` block, before the generic metadata read (right after `try {`):

```ts
    if (spec.type === 'messageClass') {
      const state = await client.getMessageClass().read({ name: spec.name });
      if (!state?.messageClass) {
        return { ...base, status: 'missing' };
      }
      const system = state.messageClass as ParsedMessageClass;
      if (system.packageName) {
        base.actualPackage = system.packageName;
      }
      if (
        expectedPackage &&
        system.packageName &&
        system.packageName.toUpperCase() !== expectedPackage.toUpperCase()
      ) {
        return {
          ...base,
          status: 'package-mismatch',
          message: `Expected package ${expectedPackage}, found ${system.packageName}`,
        };
      }
      const expectedText =
        expectedSourceBase64 !== undefined
          ? decodeBase64(expectedSourceBase64)
          : expectedSource;
      if (expectedText !== undefined) {
        const expectedCls = JSON.parse(expectedText) as ParsedMessageClass;
        if (
          canonicalizeMessageClass(system) !==
          canonicalizeMessageClass(expectedCls)
        ) {
          return {
            ...base,
            status: 'source-mismatch',
            message: 'Message class content differs from backup',
          };
        }
      }
      return base;
    }
```

- [ ] **Step 5: Add the `messageClass` branch to the `diff` command**

In `src/lib/run.ts`, locate the schemaVersion-2 single-object diff (`if (node.codeFormat === 'xml') { … } else { … }`, around line 684). Add the message-class case first. Add imports at the top of the file if missing:

```ts
import { canonicalizeMessageClass } from './messageClass/canonicalizeMessageClass';
import type { ParsedMessageClass } from './messageClass/types';
```

Replace the `if (node.codeFormat === 'xml') { … } else { … }` with a three-way branch:

```ts
        if (node.type === 'messageClass') {
          const state = await client.getMessageClass().read({ name: node.name });
          const backupCanon = canonicalizeMessageClass(
            JSON.parse(backupText) as ParsedMessageClass,
          );
          const systemCanon = state?.messageClass
            ? canonicalizeMessageClass(state.messageClass as ParsedMessageClass)
            : '';
          await diffSource(
            formatObjectSpec(spec),
            backupCanon,
            systemCanon,
            true,
          );
        } else if (node.codeFormat === 'xml') {
          const metadataXml = await readMetadataXmlForType(
            client,
            node.type!,
            node.name,
            node.functionGroupName,
          );
          if (metadataXml)
            await diffMetadata(
              formatObjectSpec(spec),
              backupText,
              metadataXml,
              true,
            );
        } else {
          const actualSource = await readSourceText(client, spec);
          await diffSource(
            formatObjectSpec(spec),
            backupText,
            actualSource ?? '',
            true,
          );
        }
```

- [ ] **Step 6: Run test to verify it passes**

Run: `npm run build:fast && npm run test:offline`
Expected: `OK task6`

- [ ] **Step 7: Lint + commit**

```bash
npm run lint
git add src/lib/messageClass/canonicalizeMessageClass.ts src/lib/verify/verifyObjectInSystem.ts src/lib/run.ts tests/offline/messageclass.cjs
git commit -m "feat(msag): verify + diff compare full message-class content"
```

---

## Task 7: Documentation

**Files:**
- Modify: `docs/roadmap.yaml`
- Modify: `docs/SMOKE_CHECKLIST.md`
- Modify: `CLAUDE.md`
- Modify: `README.md`
- Modify: `CHANGELOG.md`

**Interfaces:** none (docs only).

- [ ] **Step 1: Roadmap — add the type**

In `docs/roadmap.yaml`, add a `messageClass` entry alongside the other supported types, following the existing entry shape. Set its payload format to `source`/`json` per the file's convention for non-XML payloads (message classes store parsed JSON); note `MSAG/N`, not activatable, restored early, no co-activation. Mirror the field set of a neighboring entry (e.g. `appendStructure`).

- [ ] **Step 2: Smoke checklist — add a message-class row**

In `docs/SMOKE_CHECKLIST.md`, add a checklist item under the backup/restore section:

```markdown
- [ ] Message class (`MSAG`): backup a class with >=2 messages; restore into a scratch package; `verify` reports OK; edit one message text in the target, re-run `verify` → `source-mismatch`; re-`restore` → OK; add a stray message in the target, re-`restore` → stray removed (reconcile).
```

- [ ] **Step 3: CLAUDE.md — list the new type**

In `CLAUDE.md`, in the `SupportedType` description under *Key Types*, add `messageClass` to the enumeration and note in *Object Payload Formats* that message classes store parsed JSON (one atomic unit: class + messages), restored via shell-create + per-message upsert + reconcile, not activatable.

- [ ] **Step 4: README.md — mention message-class support**

In `README.md`, wherever the supported object types are listed, add Message Classes (`MSAG`). Keep the wording consistent with the surrounding list.

- [ ] **Step 5: CHANGELOG.md — add an Unreleased entry**

In `CHANGELOG.md`, add under a new `## [Unreleased]` section (or the existing one):

```markdown
### Added
- Message class (`MSAG`) backup/restore/verify/diff support. Class and its messages are one atomic backup unit (JSON payload); restore creates the shell, upserts messages, and reconciles (deletes target-only messages). Not activatable; restored early with no co-activation.

### Changed
- Bump `@mcp-abap-adt/adt-clients` to `^7.3.1` (adds message-class module).
```

- [ ] **Step 6: Verify build still clean + commit**

```bash
npm run build && npm run test:offline
git add docs/roadmap.yaml docs/SMOKE_CHECKLIST.md CLAUDE.md README.md CHANGELOG.md
git commit -m "docs(msag): document message-class backup/restore"
```

---

## Task 8: Live verification (PERMISSION-GATED)

**Files:** none (manual validation).

**Interfaces:** none.

> **STOP.** This task hits a live SAP system. Do **not** run any step here without asking the user first, each time, and waiting for a "yes". The trial system needs the user to activate a browser profile before auth works. Offline work (Tasks 1–7) is already complete and committed; this task only confirms the round-trip on a real system.

- [ ] **Step 1: Ask permission**

Ask: "Tasks 1–7 are done and green offline. May I run a live message-class round-trip on the trial system now (backup + restore + verify against a scratch package)? It needs the browser profile active."

Wait for explicit approval. If declined, stop here — the feature is offline-complete; live verification is deferred to the user's smoke run.

- [ ] **Step 2: Build**

```bash
npm run build
```

- [ ] **Step 3: Back up a real message class** (after approval; use `--env-path`, not `--env`)

```bash
node dist/bin/adt-backup.js backup --objects "messageClass:<EXISTING_MSAG>" --env-path trial.env --output /tmp/msag-live.backup.yaml -v
```

Expected: a schemaVersion-1 backup with the message class, `source` = JSON with all messages.

- [ ] **Step 4: Restore into a scratch package and verify**

```bash
node dist/bin/adt-backup.js restore --input /tmp/msag-live.backup.yaml --env-path trial.env -v
node dist/bin/adt-backup.js verify --input /tmp/msag-live.backup.yaml --env-path trial.env -v
```

Expected: restore completes with no activation attempt on the MSAG; verify reports `ok`.

- [ ] **Step 5: Exercise the reconcile**

In SE91 (or via a second message added to the target), add a stray message not in the backup, then re-run restore and verify:

```bash
node dist/bin/adt-backup.js restore --input /tmp/msag-live.backup.yaml --env-path trial.env -v
node dist/bin/adt-backup.js verify --input /tmp/msag-live.backup.yaml --env-path trial.env -v
```

Expected: the stray message is deleted by the reconcile; verify reports `ok`.

- [ ] **Step 6: Report results to the user**

Summarize what ran, the actual output, and any discrepancy. Do not claim success unless the commands returned success.

---

## Self-Review (completed during authoring)

- **Spec coverage:** new type (T1) ✓; JSON payload backup (T2) ✓; restore shell+upsert+reconcile (T3–T4) ✓; activation exclusion in both paths (T4: tree via `isActivatable`; flat via `ADT_TYPE_MAP` omission) ✓; ordering via `TYPE_CREATION_ORDER` + source name-scan, where-used parity (T5) ✓; full-attribute verify + diff (T6) ✓; docs + adt-clients bump (T7) ✓; live round-trip incl. reconcile (T8) ✓.
- **Placeholder scan:** none — every code step shows full code; the one fixture base64 caveat is resolved by regenerating with `base64` in T5/Step 3.
- **Type consistency:** `ParsedMessageClass`/`ParsedMessage` defined in T3 and consumed identically in T4/T6; `restoreMessageClass` signature and `isActivatable` signature match all call sites; `canonicalizeMessageClass` signature matches verify/diff/test usage.
- **Constraint:** no live command runs before T8's permission gate.
