import type { BackupTreeNode } from '../types';

export function flattenTree(node: BackupTreeNode): BackupTreeNode[] {
  const nodes: BackupTreeNode[] = [node];
  if (node.children) {
    for (const child of node.children) {
      nodes.push(...flattenTree(child));
    }
  }
  return nodes;
}
