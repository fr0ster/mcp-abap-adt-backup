import type { NodeRecord, NodeValue } from '../types';
import { collectNodeObjects } from './collectNodeObjects';

export function collectChildNodes(node: NodeRecord): NodeRecord[] {
  const nodes: NodeRecord[] = [];
  const children = node['adtcore:node'] as NodeValue | undefined;
  if (children) {
    nodes.push(...collectNodeObjects(children));
  }
  return nodes;
}
