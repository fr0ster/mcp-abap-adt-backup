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

  console.log('OK task2');
})().catch((e) => { console.error(e); process.exit(1); });
