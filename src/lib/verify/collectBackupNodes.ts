import type { BackupTreeNode } from '../types';

export function collectBackupNodes(
  node: BackupTreeNode,
  out: BackupTreeNode[],
): void {
  if (node.type) {
    out.push(node);
  }
  if (node.children && node.children.length > 0) {
    for (const child of node.children) {
      collectBackupNodes(child, out);
    }
  }
}
