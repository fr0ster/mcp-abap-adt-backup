'use strict';
// Offline assertions for document-backed objects: a table type's flat backup
// keeps its document, and diff/verify compare the definition — not the
// package alone. Runs against compiled dist/.
const assert = require('node:assert');
const { ok } = require('./answers.cjs');

const { canonicalDocument } = require('../../dist/lib/xml/canonicalDocument');
const { backupObject } = require('../../dist/lib/backup/backupObject');
const { verifyObjectInSystem } = require('../../dist/lib/verify/verifyObjectInSystem');

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
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
