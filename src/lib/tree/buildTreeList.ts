import type { BackupTreeNode } from '../types';

export interface TreeListNode {
  name: string;
  type?: string;
  adtType?: string;
  description?: string;
  usedBy?: string[];
  children?: TreeListNode[];
}

export function buildTreeList(
  node: BackupTreeNode,
  options?: { showDeps?: boolean },
): TreeListNode {
  const { children, ...nodeBase } = node;
  const listNode: TreeListNode = {
    name: nodeBase.name,
    type: nodeBase.type,
    adtType: nodeBase.adtType,
    description: nodeBase.description,
  };
  if (options?.showDeps && nodeBase.usedBy && nodeBase.usedBy.length > 0) {
    listNode.usedBy = [...nodeBase.usedBy];
  }
  if (children && children.length > 0) {
    listNode.children = children.map((child) => buildTreeList(child, options));
  }
  return listNode;
}
