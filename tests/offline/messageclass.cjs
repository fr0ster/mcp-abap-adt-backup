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

  console.log('OK task3');
})().catch((e) => { console.error(e); process.exit(1); });
