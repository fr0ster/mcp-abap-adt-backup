import type { NodeRecord } from '../types';

export function getAttribute(
  node: NodeRecord,
  keys: string[],
): string | undefined {
  for (const key of keys) {
    const value = node[key];
    if (typeof value === 'string') {
      return value;
    }
  }
  return undefined;
}
