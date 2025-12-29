import { xmlParser } from '../constants/xmlParser';
import type { NodeRecord, NodeValue } from '../types';

export type WhereUsedEntry = {
  name?: string;
  type?: string;
  parentName?: string;
  context?: 'referencing' | 'referenced' | 'unknown';
};

const NAME_KEYS = ['@_name', '@_objectName', '@_object_name'];
const TYPE_KEYS = ['@_type', '@_objectType', '@_object_type', '@_adtType'];
const PARENT_KEYS = ['@_parentName', '@_parent_name', '@_parent'];

function getAttr(record: NodeRecord, keys: string[]): string | undefined {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === 'string' && value.trim()) {
      return value;
    }
  }
  return undefined;
}

function detectContext(key: string): 'referencing' | 'referenced' | 'unknown' {
  const lowered = key.toLowerCase();
  if (lowered.includes('referencingobject')) {
    return 'referencing';
  }
  if (lowered.includes('referencedobject')) {
    return 'referenced';
  }
  return 'unknown';
}

function visitNode(
  value: NodeValue,
  entries: WhereUsedEntry[],
  context: WhereUsedEntry['context'],
): void {
  if (Array.isArray(value)) {
    for (const item of value) {
      visitNode(item as NodeValue, entries, context);
    }
    return;
  }

  if (!value || typeof value !== 'object') {
    return;
  }

  const record = value as NodeRecord;
  const name = getAttr(record, NAME_KEYS);
  const type = getAttr(record, TYPE_KEYS);
  const parentName = getAttr(record, PARENT_KEYS);
  if (name && type) {
    entries.push({ name, type, parentName, context });
  }

  for (const [key, child] of Object.entries(record)) {
    if (key.startsWith('@_')) {
      continue;
    }
    const detected = detectContext(key);
    const nextContext = detected === 'unknown' ? context : detected;
    visitNode(child as NodeValue, entries, nextContext);
  }
}

export function parseWhereUsedXml(xml: string): WhereUsedEntry[] {
  const parsed = xmlParser.parse(xml) as NodeValue;
  const entries: WhereUsedEntry[] = [];
  visitNode(parsed, entries, 'unknown');
  return entries;
}
