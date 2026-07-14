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

console.log('OK task1');

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

  // --- post-create transient lock retry ---
  // First message upsert fails twice with the EU510 "currently editing" 403,
  // then succeeds — restoreMessageClass must retry, not abort.
  function fakeFlakyClient(failFirstN) {
    let fails = failFirstN;
    const calls = { create: 0, msgUpsert: [] };
    return {
      calls,
      getMessageClass() {
        return { async create() { calls.create++; }, async update() {},
          async read() { return { messageClass: { messages: [] } }; } };
      },
      getMessageClassMessage() {
        return {
          async update(cfg) {
            if (fails > 0) {
              fails--;
              const err = new Error('Request failed with status code 403');
              err.response = { data: '<exc:exception>...EU510...currently editing...' };
              throw err;
            }
            calls.msgUpsert.push(cfg.msgno);
          },
          async delete() {},
        };
      },
    };
  }
  const flaky = fakeFlakyClient(2);
  await restoreMessageClass(flaky, parsed, {
    mode: 'create', name: 'ZMY_MSG', description: 'd', packageName: 'ZPKG',
    retryDelayMs: 1, retryAttempts: 6,
  });
  assert.deepStrictEqual(flaky.calls.msgUpsert.sort(), ['001', '002'], 'retries transient lock then upserts');

  // A non-transient error must NOT be retried — it propagates.
  const hardFail = {
    getMessageClass() { return { async create() {}, async update() {}, async read() { return { messageClass: { messages: [] } }; } }; },
    getMessageClassMessage() { return { async update() { throw new Error('boom 500'); }, async delete() {} }; },
  };
  let threw = false;
  try {
    await restoreMessageClass(hardFail, parsed, { mode: 'create', name: 'Z', retryDelayMs: 1 });
  } catch (e) { threw = /boom 500/.test(e.message); }
  assert.ok(threw, 'non-transient error propagates without retry');

  console.log('OK task6');
})().catch((e) => { console.error(e); process.exit(1); });
