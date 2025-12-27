import type { NodeRecord, NodeValue } from '../types';
import { isNodeObject } from './isNodeObject';

export function collectNodeObjects(value: NodeValue): NodeRecord[] {
  if (!value || typeof value !== 'object') {
    return [];
  }
  if (Array.isArray(value)) {
    return value.flatMap((entry) => collectNodeObjects(entry as NodeValue));
  }
  const record = value as NodeRecord;
  const results: NodeRecord[] = [];
  if (isNodeObject(record) && record['adtcore:node']) {
    results.push(record);
  }
  for (const entry of Object.values(record)) {
    results.push(...collectNodeObjects(entry));
  }
  return results;
}
