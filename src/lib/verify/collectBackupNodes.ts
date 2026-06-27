import type { BackupTreeNode } from '../types';

export function collectBackupNodes(
  node: BackupTreeNode,
  out: BackupTreeNode[],
): void {
  // Skip nodes the backup marked as not restorable (unsupported types, or objects
  // missing a required config field). They are excluded from plan/restore, so verifying
  // them would wrongly report them as missing/failed. Children are still traversed below.
  if (node.type && node.restoreStatus !== 'not-implemented') {
    out.push(node);
  }
  if (node.children && node.children.length > 0) {
    for (const child of node.children) {
      collectBackupNodes(child, out);
    }
  }
}
