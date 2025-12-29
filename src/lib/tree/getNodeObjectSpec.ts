import type { BackupTreeNode, ObjectSpec } from '../types';
import { getNodeFunctionGroupName } from './getNodeFunctionGroupName';

export function getNodeObjectSpec(
  node: BackupTreeNode,
): ObjectSpec | undefined {
  if (!node.type) {
    return undefined;
  }
  if (node.type === 'functionModule') {
    const group = getNodeFunctionGroupName(node);
    if (!group) {
      return undefined;
    }
    return {
      type: node.type,
      name: node.name,
      functionGroupName: group,
    };
  }
  return { type: node.type, name: node.name };
}
