import type { BackupTreeNode } from '../types';

export function stripVirtualGroups(root: BackupTreeNode): BackupTreeNode {
  const objects: BackupTreeNode[] = [];

  const collect = (node: BackupTreeNode): void => {
    const { children, ...nodeBase } = node;
    const isPackageNode = node.type === 'package' || node.adtType === 'DEVC/K';
    const isObjectNode = Boolean(node.adtType && node.adtType.includes('/'));
    if ((isObjectNode || isPackageNode) && node.type !== 'package') {
      objects.push(nodeBase);
    }
    if (children && children.length > 0) {
      for (const child of children) {
        collect(child);
      }
    }
  };

  if (root.children && root.children.length > 0) {
    for (const child of root.children) {
      collect(child);
    }
  }

  return {
    ...root,
    children: objects.length > 0 ? objects : [],
  };
}
