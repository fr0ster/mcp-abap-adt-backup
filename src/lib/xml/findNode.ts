import type { NodeRecord, NodeValue } from '../types';

export function findNode(
  node: NodeValue | undefined,
  keys: string[],
): NodeValue | undefined {
  if (!node || typeof node !== 'object') {
    return undefined;
  }
  if (Array.isArray(node)) {
    for (const value of node) {
      const found = findNode(value as NodeValue, keys);
      if (found !== undefined) {
        return found;
      }
    }
    return undefined;
  }
  const record = node as NodeRecord;
  for (const key of keys) {
    if (record[key] !== undefined) {
      return record[key];
    }
  }
  for (const value of Object.values(record)) {
    const found = findNode(value, keys);
    if (found !== undefined) {
      return found;
    }
  }
  return undefined;
}
