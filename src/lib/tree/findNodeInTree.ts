import type { BackupTreeNode, ObjectSpec } from '../types';

export function findNodeInTree(
  node: BackupTreeNode,
  spec: ObjectSpec,
): BackupTreeNode | undefined {
  if (
    node.type === spec.type &&
    node.name.toUpperCase() === spec.name.toUpperCase()
  ) {
    if (spec.type !== 'functionModule') {
      return node;
    }
    const configGroup =
      node.config && typeof node.config.functionGroupName === 'string'
        ? (node.config.functionGroupName as string)
        : undefined;
    const group =
      configGroup || node.functionGroupName || spec.functionGroupName;
    if (
      group &&
      spec.functionGroupName &&
      group.toUpperCase() === spec.functionGroupName.toUpperCase()
    ) {
      return node;
    }
  }

  if (!node.children) {
    return undefined;
  }

  for (const child of node.children) {
    const found = findNodeInTree(child, spec);
    if (found) {
      return found;
    }
  }

  return undefined;
}
