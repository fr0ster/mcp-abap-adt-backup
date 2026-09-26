import type { IObjectReference } from '@mcp-abap-adt/interfaces-adt';
import type { BackupTreeNode } from '../types';

/**
 * Every non-package object in the tree, once, as a reference group deletion
 * takes. A function module or include carries its group as `parentName`:
 * adt-clients addresses it under the group and refuses one without it.
 */
export function collectDeletionTargets(
  root: BackupTreeNode,
): IObjectReference[] {
  const targets: IObjectReference[] = [];
  const seen = new Set<string>();

  const visit = (node: BackupTreeNode): void => {
    if (node.adtType && node.adtType !== 'DEVC/K') {
      const key = `${node.adtType}:${node.name}`;
      if (!seen.has(key)) {
        seen.add(key);
        const target: IObjectReference = {
          name: node.name,
          type: node.adtType,
        };
        if (node.functionGroupName && node.adtType.startsWith('FUGR/')) {
          if (node.adtType !== 'FUGR/F') {
            target.parentName = node.functionGroupName;
          }
        }
        targets.push(target);
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
