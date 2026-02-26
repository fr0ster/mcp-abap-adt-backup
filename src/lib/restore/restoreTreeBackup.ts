import type { AdtClient, ObjectReference } from '@mcp-abap-adt/adt-clients';
import { logVerbose } from '../cli/logVerbose';
import { flattenTree } from '../tree/flattenTree';
import { getNodeObjectId } from '../tree/getNodeObjectId';
import type { BackupTreeNode, RestoreMode, SupportedType } from '../types';
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
  softwareComponent?: string,
  superPackageOverride?: string,
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

  const packageNodes = nodes.filter((node) => node.type === 'package');
  const nonPackageNodes = nodes.filter((node) => node.type !== 'package');
  const backupPackageNames = new Set(packageNodes.map((node) => node.name));

  const rootPackageName = root.name;

  logVerbose(1, `\n>>> STARTING RESTORE: ${nodes.length} objects (Target: ${rootPackageName})`);

  // Step 1: Packages (Hierarchy bottom-up)
  if (packageNodes.length > 0) {
    logVerbose(1, `[PHASE 1] Restoring package hierarchy...`);
    const restorePackageRecursive = async (node: BackupTreeNode, parentName?: string) => {
      if (node.type === 'package') {
        const isRootNode = node.name === rootPackageName;
        const nodeMode = (restoreActions?.get(getNodeObjectId(node)!) || mode) as RestoreMode;
        const effectiveMode = isRootNode ? 'update' : nodeMode;

        if (!restoreIds || restoreIds.has(getNodeObjectId(node)!) || isRootNode) {
          logVerbose(2, `  -> Process [PACKAGE] ${node.name} (Parent: ${parentName || superPackageOverride || 'SYSTEM ROOT'})`);
          try {
            await restoreTreeNode(client, node, effectiveMode, false, transportRequest, softwareComponent, backupPackageNames, parentName || superPackageOverride);
          } catch (e: any) {
            if (isRootNode) {
              logVerbose(1, `  ! Warning: Root package ${node.name} already exists or update skipped.`);
            } else throw e;
          }
        }
      }
      if (node.children) {
        for (const child of node.children) {
          await restorePackageRecursive(child, node.type === 'package' ? node.name : parentName);
        }
      }
    };
    await restorePackageRecursive(root, undefined);
  }

  // Step 2: Object Layers (The order matters for dependencies!)
  const activationLayers: SupportedType[][] = [
    ['domain', 'dataElement'],
    ['structure', 'table', 'tableType'],
    ['view'],
    ['functionGroup', 'functionModule'],
    ['interface', 'class', 'program'],
    ['behaviorDefinition', 'behaviorImplementation'],
    ['serviceDefinition', 'serviceBinding', 'metadataExtension'],
    ['enhancement'],
  ];

  for (let i = 0; i < activationLayers.length; i++) {
    const layerTypes = activationLayers[i];
    const layerNodes = nonPackageNodes.filter(n => n.type && layerTypes.includes(n.type));
    if (layerNodes.length === 0) continue;

    logVerbose(1, `[PHASE ${i + 2}] Restoring layer: ${layerTypes.join(', ')} (${layerNodes.length} objects)`);
    const activationList: ObjectReference[] = [];
    const sortedLayerNodes = sortTreeNodesByDependencies(layerNodes);

    for (const node of sortedLayerNodes) {
      const nodeId = getNodeObjectId(node)!;
      const nodeMode = (restoreActions?.get(nodeId) || mode) as RestoreMode;
      const shouldActivate = (nodeMode === 'create' ? activateOnCreate : activate);

      logVerbose(2, `  -> Restore [${node.type?.toUpperCase()}] ${node.name} (${nodeMode})`);
      
      try {
        await restoreTreeNode(client, node, nodeMode, false, transportRequest, softwareComponent, backupPackageNames, undefined);
        if (shouldActivate && node.adtType) {
          activationList.push({ name: node.name, type: node.adtType });
        }
      } catch (error: any) {
        logVerbose(1, `\n!!! CRITICAL FAILURE during restoration of ${node.type}:${node.name}`);
        logVerbose(1, `Reason: ${error.message}`);
        throw error; // Stop immediately to let user fix the order/dependency
      }
    }

    if (activationList.length > 0) {
      logVerbose(1, `  [*] Activating group of ${activationList.length} objects in this layer...`);
      try {
        await client.getUtils().activateObjectsGroup(activationList, true);
        logVerbose(2, `  [OK] Layer ${i + 2} activated.`);
      } catch (error: any) {
        logVerbose(1, `  [!] WARNING: Layer activation failed: ${error.message}. Some objects might be inactive.`);
      }
    }
  }

  logVerbose(1, `\n>>> RESTORE COMPLETED SUCCESSFULLY.`);
}
