import type { BackupTreeNode } from '../types';

export interface TreeListNode {
  name: string;
  type?: string;
  adtType?: string;
  description?: string;
  children?: TreeListNode[];
}

export function buildTreeList(node: BackupTreeNode): TreeListNode {
  const { children, ...nodeBase } = node;
  const listNode: TreeListNode = {
    name: nodeBase.name,
    type: nodeBase.type,
    adtType: nodeBase.adtType,
    description: nodeBase.description,
  };
  if (children && children.length > 0) {
    listNode.children = children.map(buildTreeList);
  }
  return listNode;
}
