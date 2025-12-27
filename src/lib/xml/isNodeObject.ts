import type { NodeRecord, NodeValue } from '../types';

export function isNodeObject(node: NodeValue): node is NodeRecord {
  if (!node || typeof node !== 'object') {
    return false;
  }
  if (Array.isArray(node)) {
    return false;
  }
  return true;
}
