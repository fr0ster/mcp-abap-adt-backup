import type { BackupTreeNode } from '../types';

function formatTreeNodeLabel(node: BackupTreeNode): string {
  if (node.type) {
    return `${node.type}:${node.name}`;
  }
  if (node.adtType) {
    return `${node.adtType}:${node.name}`;
  }
  return node.name;
}

export function formatTreeListText(node: BackupTreeNode, depth = 0): string[] {
  const lines: string[] = [];
  const indent = '  '.repeat(depth);
  lines.push(`${indent}${formatTreeNodeLabel(node)}`);
  if (node.children && node.children.length > 0) {
    for (const child of node.children) {
      lines.push(...formatTreeListText(child, depth + 1));
    }
  }
  return lines;
}
