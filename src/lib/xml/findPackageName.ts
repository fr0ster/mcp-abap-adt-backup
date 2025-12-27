import type { NodeRecord, NodeValue } from '../types';
import { findAttribute } from './findAttribute';

export function findPackageName(node: NodeValue): string | undefined {
  if (!node || typeof node !== 'object') {
    return undefined;
  }
  if (!Array.isArray(node)) {
    const record = node as NodeRecord;
    if (
      record['adtcore:packageRef'] &&
      typeof record['adtcore:packageRef'] === 'object'
    ) {
      const name = findAttribute(record['adtcore:packageRef'], 'adtcore:name');
      if (name) {
        return name;
      }
    }
  }
  if (Array.isArray(node)) {
    for (const value of node) {
      const found = findPackageName(value as NodeValue);
      if (found) {
        return found;
      }
    }
    return undefined;
  }
  for (const value of Object.values(node as NodeRecord)) {
    const found = findPackageName(value);
    if (found) {
      return found;
    }
  }
  return undefined;
}
