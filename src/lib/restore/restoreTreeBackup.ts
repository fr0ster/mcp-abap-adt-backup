import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import { logVerbose } from '../cli/logVerbose';
import { typeOrder } from '../constants/typeOrder';
import { flattenTree } from '../tree/flattenTree';
import type { BackupTreeNode, RestoreMode } from '../types';
import { restoreTreeNode } from './restoreTreeNode';

export async function restoreTreeBackup(
  client: AdtClient,
  root: BackupTreeNode,
  mode: RestoreMode,
  activate: boolean,
): Promise<void> {
  const nodes = flattenTree(root).filter(
    (node) => node.type && node.restoreStatus === 'ok',
  );
  const priority = new Map(typeOrder.map((type, index) => [type, index]));
  nodes.sort((a, b) => {
    const aOrder = a.type ? (priority.get(a.type) ?? 999) : 999;
    const bOrder = b.type ? (priority.get(b.type) ?? 999) : 999;
    return aOrder - bOrder || a.name.localeCompare(b.name);
  });

  logVerbose(
    2,
    `Restoring ${nodes.length} node(s) from tree (mode=${mode}, activate=${activate})`,
  );
  for (const node of nodes) {
    logVerbose(3, `Restore ${node.type}:${node.name}`);
    if (mode === 'upsert') {
      try {
        await restoreTreeNode(client, node, 'create', activate);
      } catch (_error) {
        await restoreTreeNode(client, node, 'update', activate);
      }
    } else {
      await restoreTreeNode(client, node, mode, activate);
    }
  }
}
