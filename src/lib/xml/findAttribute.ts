import type { NodeRecord, NodeValue } from '../types';

export function findAttribute(
  node: NodeValue | undefined,
  attributeName: string,
): string | undefined {
  if (!node || typeof node !== 'object') {
    return undefined;
  }
  const attrKey = `@_${attributeName}`;
  if (
    !Array.isArray(node) &&
    typeof (node as NodeRecord)[attrKey] === 'string'
  ) {
    return (node as NodeRecord)[attrKey] as string;
  }
  if (Array.isArray(node)) {
    for (const value of node) {
      const found = findAttribute(value as NodeValue, attributeName);
      if (found) {
        return found;
      }
    }
    return undefined;
  }
  for (const value of Object.values(node as NodeRecord)) {
    const found = findAttribute(value, attributeName);
    if (found) {
      return found;
    }
  }
  return undefined;
}
