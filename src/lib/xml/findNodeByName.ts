import type { NodeRecord, NodeValue } from '../types';
import { collectNodeObjects } from './collectNodeObjects';
import { getNodeName } from './getNodeName';

export function findNodeByName(
  value: NodeValue,
  name: string,
): NodeRecord | undefined {
  const candidates = collectNodeObjects(value);
  return candidates.find(
    (node) => getNodeName(node)?.toUpperCase() === name.toUpperCase(),
  );
}
