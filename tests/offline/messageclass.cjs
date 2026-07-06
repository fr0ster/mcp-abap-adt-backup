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
