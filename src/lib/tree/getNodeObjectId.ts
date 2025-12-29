import type { BackupTreeNode } from '../types';
import { objectId } from '../utils/objectId';
import { getNodeObjectSpec } from './getNodeObjectSpec';

export function getNodeObjectId(node: BackupTreeNode): string | undefined {
  const spec = getNodeObjectSpec(node);
  return spec ? objectId(spec) : undefined;
}
