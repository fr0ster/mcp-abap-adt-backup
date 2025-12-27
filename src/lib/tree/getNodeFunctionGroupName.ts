import type { BackupTreeNode } from '../types';

export function getNodeFunctionGroupName(
  node: BackupTreeNode,
): string | undefined {
  if (node.type !== 'functionModule') {
    return undefined;
  }
  const configGroup =
    node.config && typeof node.config.functionGroupName === 'string'
      ? (node.config.functionGroupName as string)
      : undefined;
  return configGroup || node.functionGroupName;
}
