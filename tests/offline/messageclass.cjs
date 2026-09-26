'use strict';
// Offline assertions for message-class support. Runs against compiled dist/.
// The fakes answer the way adt-clients 23 does: every member returns an
// IAdtResponse (`ok`, `getResult().value`, `getError()`) and does not throw
// for SAP's answer; `readMetadata()` of a message class is the raw document.
const assert = require('node:assert');
const { ok, fail } = require('./answers.cjs');

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
const { parseMessageClassXml } = require('../../dist/lib/messageClass/parseMessageClassXml');

// The shape ADT answers for GET /sap/bc/adt/messageclass/{name}.
const MSAG_XML =
  '<?xml version="1.0" encoding="UTF-8"?>' +
  '<mc:messageClass xmlns:mc="http://www.sap.com/adt/MessageClass" xmlns:adtcore="http://www.sap.com/adt/core" ' +
  'adtcore:name="ZMY_MSG" adtcore:description="My messages" adtcore:language="EN" adtcore:masterLanguage="EN" ' +
  'adtcore:responsible="SOMEONE" adtcore:type="MSAG/N">' +
  '<adtcore:packageRef adtcore:name="ZPKG"/>' +
  '<mc:messages mc:msgno="001" mc:msgtext="First" mc:selfexplainatory="false"/>' +
  '<mc:messages mc:msgno="002" mc:msgtext="Second" mc:selfexplainatory="true" adtcore:description="why"/>' +
  '</mc:messageClass>';

function fakeReadClient(xml = MSAG_XML) {
  return {
    getMessageClass() {
      return {
        async readMetadata() {
          return ok(xml);
        },
      };
    },
  };
}

const parsedFromXml = parseMessageClassXml(MSAG_XML);
assert.strictEqual(parsedFromXml.name, 'ZMY_MSG', 'parser reads the class name');
assert.strictEqual(parsedFromXml.packageName, 'ZPKG', 'parser reads the package');
assert.strictEqual(parsedFromXml.description, 'My messages', 'parser reads the class description');
assert.deepStrictEqual(
  parsedFromXml.messages,
  [
    { msgno: '001', msgtext: 'First', selfExplanatory: false },
    { msgno: '002', msgtext: 'Second', selfExplanatory: true, description: 'why' },
  ],
  'parser reads every message',
);
assert.strictEqual(parsedFromXml.responsible, undefined, 'volatile metadata is not kept');

console.log('OK task1');

(async () => {
  const client = fakeReadClient();
  const payload = await readPayloadForType(client, 'messageClass', 'ZMY_MSG');
  assert.strictEqual(payload.format, 'json', 'payload format json');
  const roundtrip = JSON.parse(payload.payload);
  assert.strictEqual(roundtrip.messages.length, 2, 'payload has 2 messages');
  assert.strictEqual(roundtrip.name, 'ZMY_MSG', 'payload has class name');

  const xml = await readMetadataXmlForType(client, 'messageClass', 'ZMY_MSG');
  assert.strictEqual(xml, MSAG_XML, 'metadata returns raw xml');

  const obj = await backupObject(client, { type: 'messageClass', name: 'ZMY_MSG' });
  assert.strictEqual(obj.config.packageName, 'ZPKG', 'flat backup config packageName');
  assert.strictEqual(JSON.parse(obj.source).messages.length, 2, 'flat backup source json');

  // A class that is not there: 404 reads as absent, not as an error.
  const missing = {
    getMessageClass() {
      return { async readMetadata() { return fail(404, 'Message class ZNOPE does not exist'); } };
    },
  };
  assert.deepStrictEqual(
    await readPayloadForType(missing, 'messageClass', 'ZNOPE'),
    {},
    'absent message class has no payload',
  );

  // --- Task 3: restore helper + activation gate ---
  const {
    restoreMessageClass,
    withClassDescription,
  } = require('../../dist/lib/messageClass/restoreMessageClass');
  const { isActivatable } = require('../../dist/lib/restore/isActivatable');

  assert.strictEqual(isActivatable('messageClass'), false, 'messageClass not activatable');
  assert.strictEqual(isActivatable('class'), true, 'class activatable');

  // The class description lives on the root; every message has one too.
  const edited = withClassDescription(MSAG_XML, 'New & "quoted"');
  assert.match(edited, /<mc:messageClass [^>]*adtcore:description="New &amp; &quot;quoted&quot;"/, 'root description set, escaped');
  assert.match(edited, /adtcore:description="why"/, 'message description untouched');
  const noRootDescription = MSAG_XML.replace(' adtcore:description="My messages"', '');
  assert.match(
    withClassDescription(noRootDescription, 'Added'),
    /^[^]*<mc:messageClass adtcore:description="Added"/,
    'description inserted on the root when it had none',
  );

  function fakeTarget(existingMsgnos, overrides = {}) {
    const calls = { create: 0, lock: 0, updateMetadata: [], unlock: 0, msgUpsert: [], msgDelete: [] };
    const classXml =
      '<mc:messageClass xmlns:mc="http://www.sap.com/adt/MessageClass" xmlns:adtcore="http://www.sap.com/adt/core" adtcore:name="ZMY_MSG" adtcore:description="old">' +
      existingMsgnos.map((n) => `<mc:messages mc:msgno="${n}" mc:msgtext="x"/>`).join('') +
      '</mc:messageClass>';
    return {
      calls,
      client: {
        getMessageClass() {
          return {
            async create() { calls.create++; return ok(''); },
            async readMetadata() { return ok(classXml); },
            async lock() { calls.lock++; return ok('LOCK1'); },
            async updateMetadata(_cfg, opts) { calls.updateMetadata.push(opts); return ok(''); },
            async unlock() { calls.unlock++; return ok(undefined); },
          };
        },
      },
      messages: {
        update: overrides.update ?? (async (cfg) => { calls.msgUpsert.push(cfg.msgno); return ok(''); }),
        async delete(cfg) { calls.msgDelete.push(cfg.msgno); return ok(''); },
      },
    };
  }

  const parsed = { name: 'ZMY_MSG', description: 'd', packageName: 'ZPKG',
    messages: [{ msgno: '001', msgtext: 'a' }, { msgno: '002', msgtext: 'b' }] };

  // create mode: shell created, both messages upserted, nothing deleted
  const c1 = fakeTarget([]);
  await restoreMessageClass(c1, parsed, { mode: 'create', name: 'ZMY_MSG', description: 'd', packageName: 'ZPKG' });
  assert.strictEqual(c1.calls.create, 1, 'create shell once');
  assert.deepStrictEqual(c1.calls.msgUpsert.sort(), ['001', '002'], 'upsert both');
  assert.deepStrictEqual(c1.calls.msgDelete, [], 'no deletes on create');
  assert.strictEqual(c1.calls.lock, 0, 'create does not rewrite the shell');

  // update mode: description differs -> read, lock, write the whole document,
  // unlock; target has extra '003' -> it must be deleted
  const c2 = fakeTarget(['001', '002', '003']);
  await restoreMessageClass(c2, parsed, { mode: 'update', name: 'ZMY_MSG', description: 'd', packageName: 'ZPKG' });
  assert.strictEqual(c2.calls.lock, 1, 'update locks the class once');
  assert.strictEqual(c2.calls.updateMetadata.length, 1, 'update writes the class document once');
  assert.strictEqual(c2.calls.updateMetadata[0].lockHandle, 'LOCK1', 'write carries the lock handle');
  assert.match(c2.calls.updateMetadata[0].source, /adtcore:description="d"/, 'write carries the new description');
  assert.strictEqual(c2.calls.unlock, 1, 'update unlocks the class');
  assert.deepStrictEqual(c2.calls.msgUpsert.sort(), ['001', '002'], 'upsert both on update');
  assert.deepStrictEqual(c2.calls.msgDelete, ['003'], 'delete target-only extra');

  // update mode, description already equal: no lock, no write
  const c3 = fakeTarget(['001']);
  await restoreMessageClass(c3, parsed, { mode: 'update', name: 'ZMY_MSG', description: 'old' });
  assert.strictEqual(c3.calls.lock, 0, 'an unchanged description is not rewritten');

  // --- Task 4: writeObject delegates message classes to the helper ---
  const { writeObject } = require('../../dist/lib/restore/writeObject');
  const treeTarget = fakeTarget([]);
  const codeBase64 = Buffer.from(JSON.stringify(parsed), 'utf8').toString('base64');
  await writeObject(treeTarget, {
    type: 'messageClass', name: 'ZMY_MSG', restoreStatus: 'ok',
    codeFormat: 'json', codeBase64, config: { name: 'ZMY_MSG' },
  }, { mode: 'create', activate: false });
  assert.strictEqual(treeTarget.calls.create, 1, 'writeObject creates shell');
  assert.deepStrictEqual(treeTarget.calls.msgUpsert.sort(), ['001', '002'], 'writeObject upserts messages');

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
  // The first message write is refused twice with the EU510 "currently
  // editing" 403, then succeeds — restoreMessageClass must retry, not abort.
  let fails = 2;
  const flaky = fakeTarget([], {
    update: async (cfg) => {
      if (fails > 0) {
        fails--;
        return fail(403, 'Message class ZMY_MSG is currently being edited (EU510)', 'ExceptionResourceNoAccess');
      }
      flaky.calls.msgUpsert.push(cfg.msgno);
      return ok('');
    },
  });
  await restoreMessageClass(flaky, parsed, {
    mode: 'create', name: 'ZMY_MSG', description: 'd', packageName: 'ZPKG',
    retryDelayMs: 1, retryAttempts: 6,
  });
  assert.deepStrictEqual(flaky.calls.msgUpsert.sort(), ['001', '002'], 'retries transient lock then upserts');

  // A refusal that is not the transient one is NOT retried — it propagates
  // with SAP's message.
  let hardCalls = 0;
  const hardFail = fakeTarget([], {
    update: async () => { hardCalls++; return fail(500, 'boom 500'); },
  });
  let threw = false;
  try {
    await restoreMessageClass(hardFail, parsed, { mode: 'create', name: 'Z', retryDelayMs: 1 });
  } catch (e) { threw = /boom 500/.test(e.message); }
  assert.ok(threw, 'non-transient refusal propagates with SAP message');
  assert.strictEqual(hardCalls, 1, 'non-transient refusal is not retried');

  // A bare 403 without the edit-lock markers is an authorization failure.
  let authCalls = 0;
  const denied = fakeTarget([], {
    update: async () => { authCalls++; return fail(403, 'No authorization'); },
  });
  await assert.rejects(
    restoreMessageClass(denied, parsed, { mode: 'create', name: 'Z', retryDelayMs: 1 }),
    /No authorization/,
    'bare 403 propagates',
  );
  assert.strictEqual(authCalls, 1, 'bare 403 is not retried');

  console.log('OK task6');
})().catch((e) => { console.error(e); process.exit(1); });
