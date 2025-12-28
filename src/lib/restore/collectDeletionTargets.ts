import type { BackupTreeNode } from '../types';

export interface DeletionTarget {
  name: string;
  type: string;
}

export function collectDeletionTargets(root: BackupTreeNode): DeletionTarget[] {
  const targets: DeletionTarget[] = [];
  const seen = new Set<string>();

  const visit = (node: BackupTreeNode): void => {
    if (node.adtType && node.adtType !== 'DEVC/K') {
      const key = `${node.adtType}:${node.name}`;
      if (!seen.has(key)) {
        seen.add(key);
        targets.push({ name: node.name, type: node.adtType });
      }
    }
    if (node.children && node.children.length > 0) {
      for (const child of node.children) {
        visit(child);
      }
    }
  };

  visit(root);
  return targets;
}
