import type { BackupTreeNode, ObjectSpec } from '../types';
import { getNodeFunctionGroupName } from './getNodeFunctionGroupName';

export function collectTreeObjects(
  node: BackupTreeNode,
  out: ObjectSpec[],
): void {
  if (node.type) {
    out.push({
      type: node.type,
      name: node.name,
      functionGroupName: getNodeFunctionGroupName(node),
    });
  }
  if (node.children && node.children.length > 0) {
    for (const child of node.children) {
      collectTreeObjects(child, out);
    }
  }
}
