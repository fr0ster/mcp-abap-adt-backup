import type { NodeRecord, NodeValue } from '../types';

export function getNodeAttribute(
  node: NodeValue | undefined,
  attributeName: string,
): string | undefined {
  if (!node || typeof node !== 'object' || Array.isArray(node)) {
    return undefined;
  }
  const attrKey = `@_${attributeName}`;
  const value = (node as NodeRecord)[attrKey];
  return typeof value === 'string' ? value : undefined;
}
