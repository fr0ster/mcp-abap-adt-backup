import type { NodeRecord } from '../types';

export function readAttr(node: NodeRecord, name: string): string | undefined {
  const value = node[`@_${name}`];
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  return undefined;
}
