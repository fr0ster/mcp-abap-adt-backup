import { flattenTree } from '../tree/flattenTree';
import { getNodeObjectId } from '../tree/getNodeObjectId';
import type { BackupTreeNode } from '../types';
import { objectId } from '../utils/objectId';
import type { VerifyEntry, VerifyStatus } from '../verify/types';

export type RestoreAction = 'create' | 'update' | 'skip' | 'error';

export type RestorePlanItem = {
  id: string;
  node: BackupTreeNode;
  status: VerifyStatus;
  action: RestoreAction;
  message?: string;
};

const ACTION_BY_STATUS: Record<VerifyStatus, RestoreAction> = {
  ok: 'skip',
  missing: 'create',
  'type-mismatch': 'error',
  'package-mismatch': 'update',
  'source-mismatch': 'update',
  unsupported: 'skip',
  error: 'error',
};

export function buildRestorePlan(
  root: BackupTreeNode,
  entries: VerifyEntry[],
): RestorePlanItem[] {
  const entryById = new Map<string, VerifyEntry>();
  for (const entry of entries) {
    entryById.set(
      objectId({
        type: entry.type,
        name: entry.name,
        functionGroupName: entry.functionGroupName,
      }),
      entry,
    );
  }

  const nodes = flattenTree(root).filter(
    (node) => node.type && node.restoreStatus === 'ok',
  );
  const plan: RestorePlanItem[] = [];

  for (const node of nodes) {
    const id = getNodeObjectId(node);
    if (!id) {
      continue;
    }
    const entry = entryById.get(id);
    if (!entry) {
      plan.push({ id, node, status: 'ok', action: 'skip' });
      continue;
    }
    plan.push({
      id,
      node,
      status: entry.status,
      action: ACTION_BY_STATUS[entry.status],
      message: entry.message,
    });
  }

  return plan;
}
