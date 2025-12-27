import type { BackupTreeNode, NodeRecord } from '../types';
import { collectChildNodes } from './collectChildNodes';
import { getNodeDescription } from './getNodeDescription';
import { getNodeName } from './getNodeName';
import { getNodeType } from './getNodeType';

export function parseNodeTree(node: NodeRecord): BackupTreeNode {
  const name = getNodeName(node) || 'UNKNOWN';
  const adtType = getNodeType(node);
  const description = getNodeDescription(node);
  const treeNode: BackupTreeNode = {
    name,
    adtType,
    description,
    restoreStatus: 'not-implemented',
  };
  const children = collectChildNodes(node);
  if (children.length > 0) {
    treeNode.children = children.map(parseNodeTree);
  }
  return treeNode;
}
