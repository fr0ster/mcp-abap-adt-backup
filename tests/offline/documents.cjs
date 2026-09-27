'use strict';
// Offline assertions for document-backed objects: a table type's flat backup
// keeps its document, and diff/verify compare the definition — not the
// package alone. Runs against compiled dist/.
const assert = require('node:assert');
const { ok } = require('./answers.cjs');

const { canonicalDocument } = require('../../dist/lib/xml/canonicalDocument');
const { backupObject } = require('../../dist/lib/backup/backupObject');
const { verifyObjectInSystem } = require('../../dist/lib/verify/verifyObjectInSystem');
const { computeBackupChecksum } = require('../../dist/lib/crypto/computeBackupChecksum');
const { dispatch } = require('../../dist/lib/run');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const YAML = require('yaml');

const tableType = (rowType, stamp) =>
  '<?xml version="1.0" encoding="utf-8"?>' +
  `<ttyp:tableType adtcore:changedAt="${stamp}" adtcore:changedBy="U${stamp}" adtcore:version="active" adtcore:responsible="R${stamp}" adtcore:name="ZTT" adtcore:type="TTYP/DA" adtcore:description="Table type" xmlns:ttyp="http://www.sap.com/dictionary/tabletype" xmlns:adtcore="http://www.sap.com/adt/core">` +
  `<atom:link href="./ztt/versions" etag="${stamp}" xmlns:atom="http://www.w3.org/2005/Atom"/>` +
  '<adtcore:packageRef adtcore:name="ZPKG"/>' +
  `<ttyp:rowType><ttyp:typeName>${rowType}</ttyp:typeName></ttyp:rowType>` +
  '<ttyp:primaryKey ttyp:isKeyDefined="true" ttyp:keyDefinition="standard"/>' +
  '</ttyp:tableType>';

const clientAnswering = (xml) => ({
  getTableType: () => ({ readMetadata: async () => ok(xml) }),
});

async function main() {
  // canonicalDocument: a save's stamps do not count, the definition does.
  assert.strictEqual(
    canonicalDocument(tableType('ZOLD_ROW', '2026-01-01')),
    canonicalDocument(tableType('ZOLD_ROW', '2026-09-27')),
    'stamps, etags and links are not the definition',
  );
  assert.notStrictEqual(
    canonicalDocument(tableType('ZOLD_ROW', '2026-01-01')),
    canonicalDocument(tableType('ZNEW_ROW', '2026-01-01')),
    'a changed row type is a changed definition',
  );
  console.log('OK canonical document');

  // backup --objects tableType: the document is kept whole.
  const xml = tableType('ZOLD_ROW', '2026-01-01');
  const object = await backupObject(clientAnswering(xml), {
    type: 'tableType',
    name: 'ZTT',
  });
  assert.strictEqual(object.source, xml, 'the flat backup holds the document');
  assert.strictEqual(object.config.packageName, 'ZPKG');
  console.log('OK flat table type backup');

  // verify: a changed row type is a mismatch; a re-saved object is not.
  const b64 = Buffer.from(xml, 'utf8').toString('base64');
  const changed = await verifyObjectInSystem(
    clientAnswering(tableType('ZNEW_ROW', '2026-09-27')),
    { type: 'tableType', name: 'ZTT' },
    'ZPKG',
    undefined,
    b64,
    'xml',
  );
  assert.strictEqual(changed.status, 'source-mismatch', JSON.stringify(changed));
  const resaved = await verifyObjectInSystem(
    clientAnswering(tableType('ZOLD_ROW', '2026-09-27')),
    { type: 'tableType', name: 'ZTT' },
    'ZPKG',
    undefined,
    b64,
    'xml',
  );
  assert.strictEqual(resaved.status, 'ok', JSON.stringify(resaved));
  console.log('OK verify compares the definition');

  // diff over a flat backup: every object compared, and the command ends
  // there — it used to fall through to "Unknown command: diff".
  const source = 'CLASS zcl_x DEFINITION.\nENDCLASS.';
  const backup = {
    schemaVersion: 1,
    generatedAt: '2026-09-27T00:00:00Z',
    objects: [
      { id: 'class:ZCL_X', type: 'class', name: 'ZCL_X', config: {}, source },
      { id: 'tableType:ZTT', type: 'tableType', name: 'ZTT', config: {}, source: xml },
    ],
  };
  backup.checksum = computeBackupChecksum(backup);
  const file = path.join(os.tmpdir(), `adt-backup-flat-${process.pid}.yaml`);
  fs.writeFileSync(file, YAML.stringify(backup));
  const printed = [];
  const log = console.log;
  console.log = (line) => printed.push(String(line));
  try {
    await dispatch(
      'diff',
      { input: file, all: true, 'show-ok': true },
      {
        getClass: () => ({ read: async () => ok(source) }),
        getTableType: () => ({
          readMetadata: async () => ok(tableType('ZNEW_ROW', '2026-09-27')),
        }),
      },
      undefined,
      undefined,
    );
  } finally {
    console.log = log;
    fs.rmSync(file, { force: true });
  }
  const out = printed.join('\n');
  assert.match(out, /=== class:ZCL_X\nNo differences/, out);
  assert.match(out, /=== tableType:ZTT[\s\S]*ZNEW_ROW/, out);
  console.log('OK diff reads a flat backup and ends');
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
