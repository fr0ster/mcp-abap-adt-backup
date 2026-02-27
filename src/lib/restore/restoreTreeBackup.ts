import type { AdtClient, ObjectReference } from '@mcp-abap-adt/adt-clients';
import { logVerbose } from '../cli/logVerbose';
import { flattenTree } from '../tree/flattenTree';
import { getNodeObjectId } from '../tree/getNodeObjectId';
import type { BackupTreeNode, RestoreMode, SupportedType } from '../types';
import { analyzeDependencies } from './analyzeDependencies';
import { restoreTreeNode } from './restoreTreeNode';

/**
 * Per-type activation strategy:
 * - 'individual': activate=true per object (SAP activates on create/update)
 * - 'bulk': collect refs, single bulkActivate for the whole phase
 * - 'cluster': run analyzeDependencies on phase nodes, bulk activate per SCC group
 */
interface RestorePhase {
  name: string;
  types: SupportedType[];
  activation: 'individual' | 'bulk' | 'cluster';
}

const RESTORE_PHASES: RestorePhase[] = [
  { name: 'Domains', types: ['domain'], activation: 'individual' },
  { name: 'Data Elements', types: ['dataElement'], activation: 'individual' },
  { name: 'Structures', types: ['structure'], activation: 'individual' },
  { name: 'Tables', types: ['table'], activation: 'individual' },
  { name: 'Table Types', types: ['tableType'], activation: 'individual' },
  { name: 'CDS Views', types: ['view'], activation: 'cluster' },
  {
    name: 'Behavior',
    types: ['behaviorDefinition', 'behaviorImplementation'],
    activation: 'bulk',
  },
  { name: 'Classes', types: ['class'], activation: 'individual' },
  { name: 'Interfaces', types: ['interface'], activation: 'individual' },
  { name: 'Programs', types: ['program'], activation: 'individual' },
  {
    name: 'Function Groups',
    types: ['functionGroup'],
    activation: 'individual',
  },
  {
    name: 'Function Modules',
    types: ['functionModule'],
    activation: 'individual',
  },
  { name: 'Access Control', types: ['accessControl'], activation: 'bulk' },
  {
    name: 'Metadata Extensions',
    types: ['metadataExtension'],
    activation: 'bulk',
  },
  {
    name: 'Service Definitions',
    types: ['serviceDefinition'],
    activation: 'bulk',
  },
  { name: 'Service Bindings', types: ['serviceBinding'], activation: 'bulk' },
  { name: 'Enhancements', types: ['enhancement'], activation: 'individual' },
];

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

  logVerbose(1, `\n>>> STARTING TYPE-PHASE RESTORE: ${nodes.length} objects`);

  const failures: { node: BackupTreeNode; error: string }[] = [];

  // Phase 1: Packages (recursive hierarchy)
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

  // Phase 2: Analyze dependencies for processing order
  logVerbose(
    1,
    `[PHASE 2] Analyzing dependencies for ${nonPackageNodes.length} objects...`,
  );
  const restoreGroups = analyzeDependencies(nonPackageNodes);
  const orderedNodes = restoreGroups.flatMap((g) => g.nodes);
  logVerbose(
    1,
    `Dependency analysis complete: ${restoreGroups.length} groups → ${orderedNodes.length} ordered nodes.`,
  );

  // Helper to bulk activate a list of refs
  const bulkActivate = async (phaseName: string, refs: ObjectReference[]) => {
    if (refs.length === 0) return;
    logVerbose(
      2,
      `  [*] Bulk activating ${phaseName} (${refs.length} objects)...`,
    );
    try {
      await client.getUtils().activateObjectsGroup(refs, true);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logVerbose(
        1,
        `  [!] WARNING: ${phaseName} activation failed: ${message}`,
      );
      logVerbose(
        1,
        '  Objects are created but might be inactive. Continuing...',
      );
    }
  };

  // Phase 3: Process by granular type phases with per-type activation strategy
  const knownTypes = new Set<SupportedType>(
    RESTORE_PHASES.flatMap((p) => p.types),
  );
  const uncategorizedNodes = orderedNodes.filter(
    (n) => n.type && !knownTypes.has(n.type) && n.type !== 'package',
  );

  // Helper: process a single node (create/update without activation)
  const processNode = async (
    node: BackupTreeNode,
    activateFlag: boolean,
  ): Promise<ObjectReference | null> => {
    const nodeId = getNodeObjectId(node);
    if (!nodeId) return null;

    const nodeMode = (restoreActions?.get(nodeId) || mode) as RestoreMode;
    if (nodeMode === 'skip') {
      logVerbose(2, `  [SKIP] ${node.type}:${node.name}`);
      return null;
    }

    const shouldActivate = nodeMode === 'create' ? activateOnCreate : activate;

    logVerbose(
      2,
      `  -> Process [${node.type?.toUpperCase()}] ${node.name} (${nodeMode})`,
    );

    try {
      await restoreTreeNode(
        client,
        node,
        nodeMode,
        activateFlag,
        transportRequest,
        softwareComponent,
        backupPackageNames,
        undefined,
        transportLayer,
      );
      if (shouldActivate && node.adtType) {
        return { name: node.name, type: node.adtType };
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.includes('status code 403')) {
        logVerbose(1, `  [SKIP] ${node.type}:${node.name} — no authorization`);
      } else {
        logVerbose(1, `  [FAIL] ${node.type}:${node.name} — ${message}`);
        failures.push({ node, error: message });
      }
    }
    return null;
  };

  const allProcessedRefs: ObjectReference[] = [];

  for (const phase of RESTORE_PHASES) {
    const phaseTypeSet = new Set(phase.types);
    const phaseNodes = orderedNodes.filter(
      (n) => n.type && phaseTypeSet.has(n.type),
    );
    if (phaseNodes.length === 0) continue;

    logVerbose(
      1,
      `[${phase.name.toUpperCase()}] Processing ${phaseNodes.length} object(s) (${phase.activation})...`,
    );

    if (phase.activation === 'individual') {
      // Activate each object at creation/update time
      for (const node of phaseNodes) {
        const ref = await processNode(node, true);
        if (ref) allProcessedRefs.push(ref);
      }
    } else if (phase.activation === 'bulk') {
      // Create/update all without activation, then bulk activate together
      const refs: ObjectReference[] = [];
      for (const node of phaseNodes) {
        const ref = await processNode(node, false);
        if (ref) refs.push(ref);
      }
      await bulkActivate(phase.name, refs);
      allProcessedRefs.push(...refs);
    } else if (phase.activation === 'cluster') {
      // Cluster by dependencies (SCC groups), bulk activate per cluster
      const groups = analyzeDependencies(phaseNodes);
      logVerbose(2, `  Dependency clustering: ${groups.length} cluster(s)`);
      for (let gi = 0; gi < groups.length; gi++) {
        const group = groups[gi];
        const clusterRefs: ObjectReference[] = [];
        for (const node of group.nodes) {
          const ref = await processNode(node, false);
          if (ref) clusterRefs.push(ref);
        }
        if (clusterRefs.length > 0) {
          await bulkActivate(
            `${phase.name} cluster ${gi + 1}/${groups.length}${group.isCircular ? ' (circular)' : ''}`,
            clusterRefs,
          );
        }
        allProcessedRefs.push(...clusterRefs);
      }
    }
  }

  // Uncategorized types (future types not in RESTORE_PHASES) — individual activation
  if (uncategorizedNodes.length > 0) {
    logVerbose(
      1,
      `[OTHER] Processing ${uncategorizedNodes.length} uncategorized object(s) (individual)...`,
    );
    for (const node of uncategorizedNodes) {
      const ref = await processNode(node, true);
      if (ref) allProcessedRefs.push(ref);
    }
  }

  // Final activation sweep — safety net for objects left inactive
  if (allProcessedRefs.length > 0) {
    logVerbose(
      1,
      `[FINAL] Activation sweep (${allProcessedRefs.length} objects)...`,
    );
    await bulkActivate('Final sweep', allProcessedRefs);
  }

  if (failures.length > 0) {
    logVerbose(
      1,
      `\n>>> RESTORE COMPLETED WITH ${failures.length} FAILURE(S):`,
    );
    for (const f of failures) {
      logVerbose(1, `  - ${f.node.type}:${f.node.name}: ${f.error}`);
    }
  } else {
    logVerbose(1, '\n>>> RESTORE COMPLETED SUCCESSFULLY.');
  }
}
