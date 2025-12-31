import type { AdtClient, ObjectReference } from '@mcp-abap-adt/adt-clients';
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
  const allNodes = flattenTree(root).filter(
    (node) => node.type && node.restoreStatus === 'ok',
  );
  const nodes = restoreIds
    ? allNodes.filter((node) => {
        const id = getNodeObjectId(node);
        return id ? restoreIds.has(id) : false;
      })
    : allNodes;

  // Separate packages from non-packages
  // Packages keep their tree order (parent before children)
  const packageNodes = nodes.filter((node) => node.type === 'package');
  const nonPackageNodes = nodes.filter((node) => node.type !== 'package');

  // Sort non-packages by dependencies or typeOrder
  const priority = new Map(typeOrder.map((type, index) => [type, index]));
  const hasDependencies = nonPackageNodes.some(
    (node) => Array.isArray(node.usedBy) && node.usedBy.length > 0,
  );
  const sortedNonPackages = hasDependencies
    ? sortTreeNodesByDependencies(nonPackageNodes)
    : nonPackageNodes.sort((a, b) => {
        const aOrder = a.type ? (priority.get(a.type) ?? 999) : 999;
        const bOrder = b.type ? (priority.get(b.type) ?? 999) : 999;
        return aOrder - bOrder || a.name.localeCompare(b.name);
      });

  // Packages first (in tree order), then sorted non-packages
  const orderedNodes = [...packageNodes, ...sortedNonPackages];

  logVerbose(
    2,
    `Restoring ${orderedNodes.length} node(s) from tree (mode=${mode}, activate=${activate})`,
  );
  logVerbose(
    2,
    `  Packages: ${packageNodes.length}, Other objects: ${sortedNonPackages.length}`,
  );

  const activationList: ObjectReference[] = [];

  for (const node of orderedNodes) {
    logVerbose(3, `Restore ${node.type}:${node.name}`);
    const nodeId = getNodeObjectId(node);
    const nodeMode =
      mode === 'upsert' && nodeId && restoreActions?.has(nodeId)
        ? restoreActions.get(nodeId)
        : mode;
    const shouldActivate = nodeMode === 'create' ? activateOnCreate : activate;
    const isPackage = node.type === 'package';
    // Defer activation for non-package objects if activation is requested
    const effectiveActivate = isPackage ? shouldActivate : false;

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

    if (!isPackage && shouldActivate && node.adtType) {
      activationList.push({ name: node.name, type: node.adtType });
    }
  }

  if (activationList.length > 0) {
    logVerbose(2, `Activating ${activationList.length} object(s)...`);
    // Pass true for preauditRequested to check before activating
    await client.getUtils().activateObjectsGroup(activationList, true);
  }
}
