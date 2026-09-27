'use strict';
// Offline assertions for the sequences the backuper composes itself on top of
// adt-clients 23: reading answers, the write sequence, the package and
// function-group walks, where-used, group activation and group deletion.
// Runs against compiled dist/. Fakes answer IAdtResponse, as adt-clients does.
const assert = require('node:assert');
const { ok, fail } = require('./answers.cjs');

const { readAnswer, requireOk } = require('../../dist/lib/adt/answer');
const { readSourceText } = require('../../dist/lib/backup/readSourceText');
const { writeObject } = require('../../dist/lib/restore/writeObject');
const { walkPackageTree } = require('../../dist/lib/tree/walkPackage');
const { functionGroupChildren } = require('../../dist/lib/tree/functionGroupChildren');
const { collectTreeDependencies } = require('../../dist/lib/dependencies/collectTreeDependencies');
const { activateGroup, activationStatusIn } = require('../../dist/lib/restore/activateGroup');
const { deleteBackupObjects } = require('../../dist/lib/restore/deleteBackupObjects');
const { resolveSystemType } = require('../../dist/lib/connection/createConnection');

const b64 = (text) => Buffer.from(text, 'utf8').toString('base64');

/** A node-structure document: `nodes` as [type, name], `types` as [type, nodeId]. */
function nodeStructure(nodes, types = []) {
  const node = ([type, name]) =>
    `<SEU_ADT_REPOSITORY_OBJ_NODE><OBJECT_TYPE>${type}</OBJECT_TYPE><OBJECT_NAME>${name}</OBJECT_NAME>` +
    `<TECH_NAME>${name}</TECH_NAME><OBJECT_URI>/x/${name}</OBJECT_URI><DESCRIPTION>${name} text</DESCRIPTION></SEU_ADT_REPOSITORY_OBJ_NODE>`;
  const info = ([type, id]) =>
    `<SEU_ADT_OBJECT_TYPE_INFO><OBJECT_TYPE>${type}</OBJECT_TYPE><NODE_ID>${id}</NODE_ID></SEU_ADT_OBJECT_TYPE_INFO>`;
  return (
    '<?xml version="1.0" encoding="utf-8"?><asx:abap version="1.0" xmlns:asx="http://www.sap.com/abapxml"><asx:values><DATA>' +
    `<TREE_CONTENT>${nodes.map(node).join('')}</TREE_CONTENT>` +
    `<OBJECT_TYPES>${types.map(info).join('')}</OBJECT_TYPES>` +
    '</DATA></asx:values></asx:abap>'
  );
}

(async () => {
  // --- reading an answer ---
  assert.strictEqual(readAnswer(ok('src'), 'read'), 'src', 'a document is the payload');
  assert.strictEqual(readAnswer(ok(''), 'read'), null, '200 with zero bytes is nothing to take');
  assert.strictEqual(readAnswer(ok('  \n'), 'read'), null, 'whitespace only is nothing to take');
  assert.strictEqual(readAnswer(fail(404, 'gone'), 'read'), null, '404 is absence');
  assert.throws(() => readAnswer(fail(403, 'No authorization'), 'read x'), /read x: HTTP 403: No authorization/, 'other failures throw with SAP text');
  assert.throws(() => requireOk(fail(500, 'dump'), 'lock y'), /lock y: HTTP 500: dump/, 'requireOk throws with SAP text');

  const emptySource = { getClass: () => ({ read: async () => ok('') }) };
  assert.strictEqual(
    await readSourceText(emptySource, { type: 'class', name: 'ZCL_X' }),
    null,
    'an empty source/main reads as nothing',
  );
  assert.strictEqual(
    await readSourceText(emptySource, { type: 'tableType', name: 'ZTT' }),
    undefined,
    'a table type has no source read',
  );

  // --- the write sequence ---
  function fakeHandler(log, overrides = {}) {
    const step = (name, answer) => async (...args) => {
      log.push({ name, args });
      return overrides[name] ? overrides[name](...args) : answer;
    };
    return {
      create: step('create', ok('')),
      lock: step('lock', ok('HANDLE')),
      update: step('update', ok('')),
      updateMetadata: step('updateMetadata', ok('')),
      unlock: step('unlock', ok(undefined)),
      activate: step('activate', ok('<chkl:messages/>')),
    };
  }
  const targetWith = (factoryName, handler) => ({
    client: { [factoryName]: () => handler },
    messages: {},
  });

  const classNode = {
    type: 'class', name: 'ZCL_X', restoreStatus: 'ok', codeFormat: 'source',
    codeBase64: b64('CLASS zcl_x DEFINITION. ENDCLASS.'),
    config: { className: 'ZCL_X', packageName: 'ZPKG', description: 'X', final: true },
  };

  let log = [];
  await writeObject(targetWith('getClass', fakeHandler(log)), classNode, {
    mode: 'create', activate: true, transportRequest: ' K900001 ',
  });
  assert.deepStrictEqual(
    log.map((s) => s.name),
    ['create', 'lock', 'update', 'unlock', 'activate'],
    'create, lock, write, unlock, activate — in that order',
  );
  const [createCfg, createOpts] = log[0].args;
  assert.deepStrictEqual(
    { name: createCfg.className, pkg: createCfg.packageName, tr: createCfg.transportRequest, final: createCfg.final },
    { name: 'ZCL_X', pkg: 'ZPKG', tr: 'K900001', final: true },
    'create config built field by field, transport trimmed',
  );
  assert.strictEqual(typeof createOpts.analyse, 'function', 'create carries an error strategy');
  assert.strictEqual('source' in createCfg, false, 'create takes no source');
  const [, updateOpts] = log[2].args;
  assert.strictEqual(updateOpts.source, 'CLASS zcl_x DEFINITION. ENDCLASS.', 'write sends the source in options.source');
  assert.strictEqual(updateOpts.lockHandle, 'HANDLE', 'write carries the lock handle');
  assert.strictEqual(log[3].args[1], 'HANDLE', 'unlock releases the same handle');

  log = [];
  await writeObject(targetWith('getClass', fakeHandler(log)), classNode, { mode: 'update', activate: false });
  assert.deepStrictEqual(log.map((s) => s.name), ['lock', 'update', 'unlock'], 'update mode: no create, no activation');

  log = [];
  await assert.rejects(
    writeObject(
      targetWith('getClass', fakeHandler(log, { update: async () => fail(423, 'invalid lock handle') })),
      classNode,
      { mode: 'update', activate: true },
    ),
    /write class ZCL_X: HTTP 423: invalid lock handle/,
    'a refused write is reported with SAP text',
  );
  assert.deepStrictEqual(log.map((s) => s.name), ['lock', 'update', 'unlock'], 'unlock runs after a failed write; no activation');

  log = [];
  await assert.rejects(
    writeObject(targetWith('getClass', fakeHandler(log, { lock: async () => ok('') })), classNode, { mode: 'update', activate: false }),
    /without a lock handle/,
    'an empty lock handle stops the sequence',
  );
  assert.deepStrictEqual(log.map((s) => s.name), ['lock'], 'nothing is written without a handle');

  log = [];
  await assert.rejects(
    writeObject(targetWith('getClass', fakeHandler(log, { activate: async () => fail(200, 'syntax error') })), classNode, { mode: 'update', activate: true }),
    /activate class ZCL_X/,
    'a refused activation is a failure',
  );

  // A document type writes the backed-up document with updateMetadata.
  log = [];
  const domainXml = '<doma:domain adtcore:name="ZD"><doma:content/></doma:domain>';
  await writeObject(
    targetWith('getDomain', fakeHandler(log)),
    { type: 'domain', name: 'ZD', restoreStatus: 'ok', codeFormat: 'xml', codeBase64: b64(domainXml), config: { packageName: 'ZPKG', datatype: 'CHAR' } },
    { mode: 'create', activate: false },
  );
  assert.deepStrictEqual(log.map((s) => s.name), ['create', 'lock', 'updateMetadata', 'unlock'], 'domain: create then write its document');
  assert.strictEqual(log[2].args[1].source, domainXml, 'the backed-up document is written whole');
  assert.strictEqual('datatype' in log[0].args[0], false, 'fields the create config lacks are not smuggled in');

  // An older backup recorded a table type as "source"; it is still its document.
  log = [];
  await writeObject(
    targetWith('getTableType', fakeHandler(log)),
    { type: 'tableType', name: 'ZTT', restoreStatus: 'ok', codeFormat: 'source', codeBase64: b64('<ttyp:tableType/>'), config: {} },
    { mode: 'update', activate: false },
  );
  assert.deepStrictEqual(log.map((s) => s.name), ['lock', 'updateMetadata', 'unlock'], 'table type written as document');

  // A package is created when missing, and left alone when it exists.
  log = [];
  const pkgNode = { type: 'package', name: 'ZCHILD', restoreStatus: 'ok', config: { packageName: 'ZCHILD', superPackage: 'ZSRC_ROOT', softwareComponent: 'HOME' } };
  await writeObject(targetWith('getPackage', fakeHandler(log)), pkgNode, { mode: 'update', activate: false });
  assert.deepStrictEqual(log, [], 'an existing package is not rewritten');
  const realSetTimeout = global.setTimeout;
  global.setTimeout = (fn) => realSetTimeout(fn, 0);
  try {
    await writeObject(targetWith('getPackage', fakeHandler(log)), pkgNode, {
      mode: 'create', activate: false, superPackage: 'ZTARGET', softwareComponent: 'ZLOCAL',
      backupPackageNames: new Set(['ZCHILD']),
    });
  } finally {
    global.setTimeout = realSetTimeout;
  }
  assert.deepStrictEqual(log.map((s) => s.name), ['create'], 'a missing package is created, nothing more');
  assert.strictEqual(log[0].args[0].superPackage, 'ZTARGET', 'super package outside the backup is overridden');
  assert.strictEqual(log[0].args[0].softwareComponent, 'ZLOCAL', 'software component override applies');

  // Skip mode and not-implemented nodes make no request at all.
  log = [];
  await writeObject(targetWith('getClass', fakeHandler(log)), classNode, { mode: 'skip', activate: true });
  await writeObject(targetWith('getClass', fakeHandler(log)), { ...classNode, restoreStatus: 'not-implemented' }, { mode: 'create', activate: true });
  assert.deepStrictEqual(log, [], 'skip and not-implemented write nothing');

  // --- the package walk ---
  const calls = [];
  const walkClient = (structures, packageAnswer = ok('<pak:package adtcore:description="Root pkg"/>')) => ({
    getPackage: () => ({ readMetadata: async () => packageAnswer }),
    getUtils: () => ({
      async fetchNodeStructure(parentType, parentName, options) {
        calls.push([parentType, parentName, options.nodeId]);
        return ok(structures[`${parentName}:${options.nodeId ?? ''}`] ?? '');
      },
    }),
  });
  const tree = await walkPackageTree(
    walkClient({
      'ZROOT:': nodeStructure([['DEVC/K', 'ZSUB']], [['CLAS/OC', '000010'], ['DEVC/K', '000001']]),
      'ZROOT:000010': nodeStructure([['CLAS/OC', 'ZCL_A'], ['CLAS/OC', 'ZCL_A']]),
      'ZSUB:': '',
    }),
    'zroot',
  );
  assert.strictEqual(tree.name, 'ZROOT', 'root upper-cased');
  assert.strictEqual(tree.description, 'Root pkg', 'root description from /packages');
  assert.deepStrictEqual(
    tree.children.map((c) => [c.adtType, c.name, (c.children ?? []).length]),
    [['DEVC/K', 'ZSUB', 0], ['CLAS/OC', 'ZCL_A', 0]],
    'subpackage descended, objects collected once',
  );
  assert.ok(!calls.some(([, , id]) => id === '000001'), 'the package-type node is not fetched as objects');

  await assert.rejects(
    walkPackageTree(walkClient({}, fail(404, 'Package ZNOPE does not exist')), 'ZNOPE'),
    /Package not found: ZNOPE/,
    'a missing root package is an error, not an empty tree',
  );
  const empty = await walkPackageTree(walkClient({}), 'ZEMPTY');
  assert.deepStrictEqual(empty, { name: 'ZEMPTY', adtType: 'DEVC/K', description: 'Root pkg' }, 'an existing empty package is an empty level');

  // --- function group children ---
  const fugrClient = {
    getUtils: () => ({
      async fetchNodeStructure(_t, _n, options) {
        if (options.nodeId === '000000') return ok(nodeStructure([], [['FUGR/FF', '000005'], ['FUGR/I', '000006']]));
        if (options.nodeId === '000005') return ok(nodeStructure([['FUGR/FF', 'Z_FM_A'], ['FUGR/FF', 'z_fm_a'], ['FUGR/FF', 'Z_FM_B']]));
        return ok('');
      },
    }),
  };
  assert.deepStrictEqual(await functionGroupChildren(fugrClient, 'zfg', 'FUGR/FF'), ['Z_FM_A', 'Z_FM_B'], 'function modules, deduped');
  assert.deepStrictEqual(await functionGroupChildren(fugrClient, 'zfg', 'FUGR/I'), [], 'an empty child node is no children');

  // --- where-used ---
  const whereUsedCalls = [];
  const depsClient = (scopeAnswer) => ({
    getUtils: () => ({
      async getWhereUsedScope(params) { whereUsedCalls.push(['scope', params.object_type]); return scopeAnswer; },
      modifyWhereUsedScope(xml, options) { whereUsedCalls.push(['modify', options.enableAll]); return `${xml}+all`; },
      async getWhereUsed(params) {
        whereUsedCalls.push(['search', params.object_type, params.scopeXml]);
        if (params.object_name !== 'ZIF_A') return ok({ totalReferences: 0, resultDescription: '', references: [] });
        return ok({ totalReferences: 1, resultDescription: '', references: [{ name: 'ZCL_A', type: 'CLAS/OC', uri: '/x', isResult: true }] });
      },
    }),
  });
  const depRoot = {
    name: 'ZROOT', adtType: 'DEVC/K', type: 'package', restoreStatus: 'not-implemented',
    children: [
      { name: 'ZIF_A', adtType: 'INTF/OI', type: 'interface', restoreStatus: 'ok' },
      { name: 'ZCL_A', adtType: 'CLAS/OC', type: 'class', restoreStatus: 'ok' },
      { name: 'ZMSG', adtType: 'MSAG/N', type: 'messageClass', restoreStatus: 'ok' },
    ],
  };
  await collectTreeDependencies(depsClient(ok('<scope/>')), depRoot);
  assert.deepStrictEqual(depRoot.children[0].usedBy, ['class:ZCL_A'], 'where-used result recorded');
  assert.deepStrictEqual(
    whereUsedCalls.slice(0, 3),
    [['scope', 'INTF/OI'], ['modify', true], ['search', 'INTF/OI', '<scope/>+all']],
    'scope, enable all types, search with that scope — interface as INTF/OI',
  );
  assert.ok(!whereUsedCalls.some((c) => c[1] === 'MSAG/N'), 'a message class is not asked about');
  whereUsedCalls.length = 0;
  depRoot.children[0].usedBy = undefined;
  await collectTreeDependencies(depsClient(fail(404, 'no scope resource')), depRoot);
  assert.deepStrictEqual(whereUsedCalls[1], ['search', 'INTF/OI', undefined], 'no scope resource: unscoped search');

  // --- group activation ---
  assert.strictEqual(activationStatusIn('<runs:run xmlns:runs="x" runs:status="finished"/>'), 'finished');
  assert.strictEqual(activationStatusIn('<run/>'), '');
  const activationLog = [];
  const runStates = ['running', 'finished'];
  const activationClient = (results) => ({
    getUtils: () => ({
      async activateObjectsGroup(refs) { activationLog.push(['start', refs.length]); return ok('RUN1'); },
      async getActivationRun(runId, options) {
        activationLog.push(['run', runId, options.withLongPolling]);
        return ok(`<runs:run runs:status="${runStates.shift() ?? 'finished'}"/>`);
      },
      async getActivationResults(runId) { activationLog.push(['results', runId]); return results; },
    }),
  });
  const refs = [{ name: 'ZCL_A', type: 'CLAS/OC' }];
  let outcome = await activateGroup(activationClient(ok('<chkl:messages/>')), refs);
  assert.deepStrictEqual(outcome, { ok: true, messages: [] }, 'finished run with clean results');
  assert.deepStrictEqual(
    activationLog,
    [['start', 1], ['run', 'RUN1', true], ['run', 'RUN1', true], ['results', 'RUN1']],
    'start, poll with long polling until finished, then results',
  );
  const refusal = fail(200, 'Activation failed');
  refusal.getError().messages = [{ type: 'E', text: 'Syntax error in ZCL_A' }];
  outcome = await activateGroup(activationClient(refusal), refs);
  assert.deepStrictEqual(outcome, { ok: false, messages: ['[E] Syntax error in ZCL_A'] }, 'SAP messages of a refused activation');
  const stuck = {
    getUtils: () => ({
      async activateObjectsGroup() { return ok('RUN2'); },
      async getActivationRun() { return ok('<run status="running"/>'); },
      async getActivationResults() { throw new Error('not reached'); },
    }),
  };
  outcome = await activateGroup(stuck, refs, 0);
  assert.strictEqual(outcome.ok, false, 'a run past the deadline is not a success');
  assert.match(outcome.messages[0], /did not finish/, 'and says so');

  // --- group deletion ---
  const deletionCalls = [];
  const deletionClient = (checkAnswer) => ({
    getUtils: () => ({
      async checkDeletionGroup(targets, options) { deletionCalls.push(['check', targets, typeof options.analyse]); return checkAnswer; },
      async deleteObjectsGroup(targets, tr) { deletionCalls.push(['delete', targets.length, tr]); return ok('<del:deletionResult/>'); },
    }),
  });
  const backup = {
    schemaVersion: 2, generatedAt: '', package: 'ZROOT',
    root: {
      name: 'ZROOT', adtType: 'DEVC/K',
      children: [
        { name: 'ZFG', adtType: 'FUGR/F', functionGroupName: 'ZFG', children: [
          { name: 'Z_FM', adtType: 'FUGR/FF', functionGroupName: 'ZFG' },
        ] },
      ],
    },
  };
  await deleteBackupObjects(deletionClient(ok('<del:checkResponse/>')), backup, ' K1 ');
  assert.deepStrictEqual(
    deletionCalls[0][1],
    [{ name: 'ZFG', type: 'FUGR/F' }, { name: 'Z_FM', type: 'FUGR/FF', parentName: 'ZFG' }],
    'targets without packages; a function module carries its group',
  );
  assert.strictEqual(deletionCalls[0][2], 'function', 'the check is judged by a strategy');
  assert.deepStrictEqual(deletionCalls[1], ['delete', 2, 'K1'], 'delete runs after a clean check');
  deletionCalls.length = 0;
  await assert.rejects(
    deleteBackupObjects(deletionClient(fail(200, 'Object is locked by another user')), backup),
    /Deletion check failed before cleanup: .*locked by another user/,
    'a refused check stops the deletion with SAP text',
  );
  assert.strictEqual(deletionCalls.length, 1, 'nothing deleted after a refused check');

  // --- the stated system type ---
  const saved = process.env.SAP_SYSTEM_TYPE;
  delete process.env.SAP_SYSTEM_TYPE;
  assert.throws(() => resolveSystemType(undefined), /not stated/, 'no system type is an error');
  assert.strictEqual(resolveSystemType('Cloud'), 'cloud', 'flag, case-insensitive');
  process.env.SAP_SYSTEM_TYPE = 'onprem # from .env';
  assert.strictEqual(resolveSystemType(undefined), 'onprem', 'from SAP_SYSTEM_TYPE');
  assert.throws(() => resolveSystemType('s4'), /Unknown system type/, 'unknown value refused');
  if (saved === undefined) delete process.env.SAP_SYSTEM_TYPE;
  else process.env.SAP_SYSTEM_TYPE = saved;

  // --- a service binding: activated before it is published, published under its lock ---
  const bindingNode = {
    type: 'serviceBinding', name: 'ZSB_X', restoreStatus: 'ok',
    config: {
      bindingName: 'ZSB_X', packageName: 'ZPKG', description: 'X',
      serviceDefinitionName: 'ZSD_X', serviceName: 'ZSD_X', serviceVersion: '0001',
      bindingVariant: 'ODATA_V4_WEB_API', desiredPublicationState: 'published', serviceType: 'odatav4',
    },
  };
  log = [];
  await writeObject(targetWith('getServiceBinding', fakeHandler(log)), bindingNode, { mode: 'create', activate: true });
  const bindingSteps = log.map((s) => s.name);
  assert.deepStrictEqual(
    bindingSteps.slice(0, 5),
    ['create', 'activate', 'lock', 'update', 'unlock'],
    'a new binding is activated before it is published, and published under its lock',
  );
  const publishOptions = log[3].args[1];
  assert.ok(publishOptions.timeout >= 10 * 60 * 1000, 'the publication gets a long timeout');
  assert.strictEqual(log[4].args[1], 'HANDLE', 'the publication lock is released');

  log = [];
  await assert.rejects(
    writeObject(
      targetWith('getServiceBinding', fakeHandler(log, { update: async () => fail(200, 'Local Publish of ZSB_X failed') })),
      { ...bindingNode },
      { mode: 'update', activate: false },
    ),
    /publish serviceBinding ZSB_X/,
    'a refused publication is a failure',
  );
  assert.deepStrictEqual(log.map((s) => s.name), ['lock', 'update', 'unlock'], 'the lock is released after a refused publication');

  // an editor holding the binding's lock: publish without it, no unlock
  log = [];
  const held = { ok: false, getError: () => ({ origin: 'connection', message: 'User X is currently editing ZSB_X', response: { status: 403, data: '' } }) };
  const editorHandler = fakeHandler(log, {
    lock: async (_config, options) => {
      const judged = options.analyse(held.getError(), undefined);
      return judged === 'adt:no-failure' ? ok('') : held;
    },
  });
  await writeObject(targetWith('getServiceBinding', editorHandler), bindingNode, { mode: 'update', activate: false });
  assert.deepStrictEqual(log.map((s) => s.name), ['lock', 'update'], 'an editor-held lock: publish without it, nothing to unlock');

  log = [];
  const stale = { origin: 'connection', message: 'Request failed with status code 423', response: { status: 423, data: '' } };
  const staleHandler = fakeHandler(log, {
    lock: async (_config, options) => {
      const judged = options.analyse(stale, undefined);
      return judged === 'adt:no-failure' ? ok('') : { ok: false, getError: () => judged };
    },
  });
  await assert.rejects(
    writeObject(targetWith('getServiceBinding', staleHandler), bindingNode, { mode: 'update', activate: false }),
    /lock serviceBinding ZSB_X/,
    'a refusal other than 403 still stops the publication',
  );

  // the unlock after a publication is judged too
  log = [];
  await assert.rejects(
    writeObject(
      targetWith('getServiceBinding', fakeHandler(log, { unlock: async () => fail(500, 'unlock failed') })),
      { ...bindingNode },
      { mode: 'update', activate: false },
    ),
    /unlock serviceBinding ZSB_X/,
    'a failed unlock after a successful publication is a failure',
  );
  log = [];
  await assert.rejects(
    writeObject(
      targetWith('getServiceBinding', fakeHandler(log, {
        update: async () => fail(200, 'Local Publish of ZSB_X failed'),
        unlock: async () => fail(500, 'unlock failed'),
      })),
      { ...bindingNode },
      { mode: 'update', activate: false },
    ),
    /publish serviceBinding ZSB_X/,
    'when both fail, the publication is the error reported',
  );
  assert.deepStrictEqual(log.map((s) => s.name), ['lock', 'update', 'unlock'], 'the unlock still ran');

  // an exception thrown during the publication still releases the lock
  log = [];
  await assert.rejects(
    writeObject(
      targetWith('getServiceBinding', fakeHandler(log, { update: async () => { throw new TypeError('reading the job answer blew up'); } })),
      { ...bindingNode },
      { mode: 'update', activate: false },
    ),
    /reading the job answer blew up/,
    'the thrown error is the one reported',
  );
  assert.deepStrictEqual(log.map((s) => s.name), ['lock', 'update', 'unlock'], 'the unlock runs after a thrown publication');

  console.log('OK sequences');
})().catch((e) => { console.error(e); process.exit(1); });
