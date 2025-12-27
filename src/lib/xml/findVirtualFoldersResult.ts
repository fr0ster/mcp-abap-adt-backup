import type { NodeRecord, NodeValue } from '../types';

export function findVirtualFoldersResult(
  value: NodeValue,
): NodeRecord | undefined {
  if (!value || typeof value !== 'object') {
    return undefined;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = findVirtualFoldersResult(item as NodeValue);
      if (found) {
        return found;
      }
    }
    return undefined;
  }
  const record = value as NodeRecord;
  for (const [key, entry] of Object.entries(record)) {
    if (
      key === 'virtualFoldersResult' ||
      key.endsWith(':virtualFoldersResult')
    ) {
      return entry as NodeRecord;
    }
  }
  for (const entry of Object.values(record)) {
    const found = findVirtualFoldersResult(entry);
    if (found) {
      return found;
    }
  }
  return undefined;
}
