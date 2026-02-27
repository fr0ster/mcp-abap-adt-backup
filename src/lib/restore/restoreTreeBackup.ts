import type { AdtClient, ObjectReference } from '@mcp-abap-adt/adt-clients';
import { logVerbose } from '../cli/logVerbose';
import { flattenTree } from '../tree/flattenTree';
import { getNodeObjectId } from '../tree/getNodeObjectId';
import type { BackupTreeNode, RestoreMode } from '../types';
import { analyzeDependencies } from './analyzeDependencies';
import { restoreTreeNode } from './restoreTreeNode';

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
  transportLayer?: string,
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

  logVerbose(
    1,
    `\n>>> STARTING TWO-STEP DEPENDENCY-AWARE RESTORE: ${nodes.length} objects`,
  );

  // Step 1: Packages (Hierarchy bottom-up)
  if (packageNodes.length > 0) {
    logVerbose(1, '[PHASE 1] Restoring package hierarchy...');
    const restorePackageRecursive = async (
      node: BackupTreeNode,
      parentName?: string,
    ) => {
      const nodeId = getNodeObjectId(node);
      if (
        node.type === 'package' &&
        nodeId &&
        (!restoreIds || restoreIds.has(nodeId))
      ) {
        const isRootNode = node.name === rootPackageName;
        const nodeMode = (restoreActions?.get(nodeId) || mode) as RestoreMode;
        const effectiveMode = isRootNode ? 'update' : nodeMode;

        if (effectiveMode === 'skip') {
          logVerbose(2, `  [SKIP] package:${node.name}`);
        } else {
          logVerbose(2, `  [PACKAGE] ${node.name}`);
          try {
            await restoreTreeNode(
              client,
              node,
              effectiveMode,
              false,
              transportRequest,
              softwareComponent,
              backupPackageNames,
              parentName || superPackageOverride,
              transportLayer,
            );
          } catch (e) {
            if (isRootNode) {
              logVerbose(
                1,
                `  ! Warning: Root package ${node.name} already exists or update skipped.`,
              );
            } else {
              throw e;
            }
          }
        }
      }
      if (node.children) {
        for (const child of node.children) {
          await restorePackageRecursive(
            child,
            node.type === 'package' ? node.name : parentName,
          );
        }
      }
    };
    await restorePackageRecursive(root, undefined);
  }

  // Step 2: Advanced Dependency Analysis
  logVerbose(
    1,
    `[PHASE 2] Analyzing code-based dependencies for ${nonPackageNodes.length} objects...`,
  );
  const restoreGroups = analyzeDependencies(nonPackageNodes);
  logVerbose(1, `Found ${restoreGroups.length} independent activation groups.`);

  // Step 3: Execution of Groups
  for (let i = 0; i < restoreGroups.length; i++) {
    const group = restoreGroups[i];
    const groupLabel =
      group.nodes.length === 1
        ? `${group.nodes[0].type}:${group.nodes[0].name}`
        : `${group.nodes.length} objects (circular group)`;

    logVerbose(
      1,
      `[GROUP ${i + 1}/${restoreGroups.length}] Restoring ${groupLabel}...`,
    );

    const activationList: ObjectReference[] = [];

    // 3a. Create/Update all objects in group as INACTIVE
    for (const node of group.nodes) {
      const nodeId = getNodeObjectId(node);
      if (!nodeId) continue;

      const nodeMode = (restoreActions?.get(nodeId) || mode) as RestoreMode;

      if (nodeMode === 'skip') {
        logVerbose(2, `  [SKIP] ${node.type}:${node.name}`);
        continue;
      }

      const shouldActivate =
        nodeMode === 'create' ? activateOnCreate : activate;

      logVerbose(
        2,
        `  -> Process [${node.type?.toUpperCase()}] ${node.name} (${nodeMode})`,
      );

      try {
        await restoreTreeNode(
          client,
          node,
          nodeMode,
          false,
          transportRequest,
          softwareComponent,
          backupPackageNames,
          undefined,
          transportLayer,
        );
        if (shouldActivate && node.adtType) {
          activationList.push({ name: node.name, type: node.adtType });
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        const is403 = message.includes('status code 403');
        if (is403) {
          logVerbose(
            1,
            `  [SKIP] ${node.type}:${node.name} — no authorization, skipped`,
          );
        } else {
          logVerbose(
            1,
            `\n!!! CRITICAL FAILURE: Failed to create ${node.type}:${node.name}`,
          );
          logVerbose(1, `Reason: ${message}`);
          throw error;
        }
      }
    }

    // 3b. Bulk Activate the group
    if (activationList.length > 0) {
      logVerbose(
        2,
        `  [*] Bulk activating group (${activationList.length} objects)...`,
      );
      try {
        await client.getUtils().activateObjectsGroup(activationList, true);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        logVerbose(1, `  [!] WARNING: Group activation failed: ${message}`);
        logVerbose(
          1,
          '  Objects are created but might be inactive. Continuing...',
        );
      }
    }
  }

  logVerbose(1, '\n>>> RESTORE COMPLETED SUCCESSFULLY.');
}
