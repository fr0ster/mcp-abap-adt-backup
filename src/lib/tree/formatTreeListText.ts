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

export function formatTreeListText(
  node: BackupTreeNode,
  depth = 0,
  options?: { showDeps?: boolean },
): string[] {
  const lines: string[] = [];
  const indent = '  '.repeat(depth);
  const depsSuffix =
    options?.showDeps && node.usedBy && node.usedBy.length > 0
      ? ` usedBy=[${node.usedBy.join(', ')}]`
      : '';
  lines.push(`${indent}${formatTreeNodeLabel(node)}${depsSuffix}`);
  if (node.children && node.children.length > 0) {
    for (const child of node.children) {
      lines.push(...formatTreeListText(child, depth + 1, options));
    }
  }
  return lines;
}
