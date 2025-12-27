import type { NodeValue } from '../types';
import { findNode } from './findNode';

export function findNodeValue(
  node: NodeValue | undefined,
  keys: string[],
): string | undefined {
  const found = findNode(node, keys);
  if (typeof found === 'string' || typeof found === 'number') {
    return String(found);
  }
  return undefined;
}
