import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import { logVerbose } from '../cli/logVerbose';
import { typeOrder } from '../constants/typeOrder';
import { flattenTree } from '../tree/flattenTree';
import { getNodeObjectId } from '../tree/getNodeObjectId';
import type { BackupTreeNode, RestoreMode } from '../types';
import { restoreTreeNode } from './restoreTreeNode';
import { sortTreeNodesByDependencies } from './sortTreeNodesByDependencies';

export async function restoreTreeBackup(
  client: AdtClient,
  root: BackupTreeNode,
  mode: RestoreMode,
  activate: boolean,
  transportRequest?: string,
  restoreIds?: Set<string>,
  restoreActions?: Map<string, RestoreMode>,
  activateOnCreate = true,
): Promise<void> {
  const nodes = flattenTree(root).filter(
    (node) => node.type && node.restoreStatus === 'ok',
  );
  const filteredNodes = restoreIds
    ? nodes.filter((node) => {
        const id = getNodeObjectId(node);
        return id ? restoreIds.has(id) : false;
      })
    : nodes;
  const priority = new Map(typeOrder.map((type, index) => [type, index]));
  const hasDependencies = filteredNodes.some(
    (node) => Array.isArray(node.usedBy) && node.usedBy.length > 0,
  );
  const orderedNodes = hasDependencies
    ? sortTreeNodesByDependencies(filteredNodes)
    : filteredNodes.sort((a, b) => {
        const aOrder = a.type ? (priority.get(a.type) ?? 999) : 999;
        const bOrder = b.type ? (priority.get(b.type) ?? 999) : 999;
        return aOrder - bOrder || a.name.localeCompare(b.name);
      });

  logVerbose(
    2,
    `Restoring ${orderedNodes.length} node(s) from tree (mode=${mode}, activate=${activate})`,
  );
  for (const node of orderedNodes) {
    logVerbose(3, `Restore ${node.type}:${node.name}`);
    const nodeId = getNodeObjectId(node);
    const nodeMode =
      mode === 'upsert' && nodeId && restoreActions?.has(nodeId)
        ? restoreActions.get(nodeId)
        : mode;
    const effectiveActivate =
      nodeMode === 'create' ? activateOnCreate : activate;
    if (nodeMode === 'upsert') {
      try {
        await restoreTreeNode(
          client,
          node,
          'create',
          effectiveActivate,
          transportRequest,
        );
      } catch (_error) {
        await restoreTreeNode(
          client,
          node,
          'update',
          effectiveActivate,
          transportRequest,
        );
      }
    } else {
      await restoreTreeNode(
        client,
        node,
        nodeMode || mode,
        effectiveActivate,
        transportRequest,
      );
    }
  }
}
