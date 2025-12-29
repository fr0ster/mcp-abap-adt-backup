import type { BackupTreeNode } from '../types';

export function stripCodeFromTree(node: BackupTreeNode): BackupTreeNode {
  const cleaned: BackupTreeNode = {
    name: node.name,
    adtType: node.adtType,
    type: node.type,
    description: node.description,
    functionGroupName: node.functionGroupName,
    usedBy: node.usedBy,
  };
  if (node.type) {
    cleaned.restoreStatus = node.restoreStatus;
  }
  if (node.children && node.children.length > 0) {
    cleaned.children = node.children.map(stripCodeFromTree);
  }
  return cleaned;
}
