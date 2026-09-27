import type { IObjectReference } from '@mcp-abap-adt/interfaces-adt';
import { AdtCallError } from '../adt/answer';
import type { RestoreTarget } from '../adt/RestoreTarget';
import { logVerbose } from '../cli/logVerbose';
import { flattenTree } from '../tree/flattenTree';
import { getNodeObjectId } from '../tree/getNodeObjectId';
import type {
  BackupTreeNode,
  RestoreMode,
  RestorePlanGroup,
  SupportedType,
} from '../types';
import { activateGroup, findInactive } from './activateGroup';
import { analyzeDependencies } from './analyzeDependencies';
import { isActivatable } from './isActivatable';
import { objectReference } from './objectReference';
import { writeObject } from './writeObject';

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
  {
    name: 'Message Classes',
    types: ['messageClass'],
    activation: 'individual',
  },
  { name: 'Structures', types: ['structure'], activation: 'individual' },
  { name: 'Tables', types: ['table'], activation: 'individual' },
  {
    name: 'Append Structures',
    types: ['appendStructure'],
    activation: 'individual',
  },
  { name: 'Table Types', types: ['tableType'], activation: 'individual' },
  {
    name: 'Scalar Functions',
    types: ['scalarFunction', 'scalarFunctionImplementation'],
    activation: 'cluster',
  },
  {
    name: 'DDL (CDS Views & Table Functions)',
    types: ['ddl'],
    activation: 'cluster',
  },
  {
    name: 'Behavior',
    types: ['behaviorDefinition', 'behaviorImplementation'],
    activation: 'bulk',
  },
  { name: 'Classes', types: ['class'], activation: 'individual' },
  { name: 'Interfaces', types: ['interface'], activation: 'individual' },
  { name: 'Programs', types: ['program'], activation: 'individual' },
  {
    name: 'Transformations',
    types: ['transformation'],
    activation: 'individual',
  },
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

/**
 * What a restore left behind: the objects that failed, and the objects it
 * processed that are still inactive. Both are failures of the restore — the
 * summary line alone used to say "successfully" over either.
 */
export interface RestoreOutcome {
  failed: number;
  inactive: number;
}

export async function restoreTreeBackup(
  target: RestoreTarget,
  root: BackupTreeNode,
  mode: RestoreMode,
  activate: boolean,
  transportRequest?: string,
  restoreIds?: Set<string>,
  planGroups?: RestorePlanGroup[],
  activateOnCreate = true,
  softwareComponent?: string,
  superPackageOverride?: string,
  transportLayer?: string,
): Promise<RestoreOutcome> {
  const { client } = target;
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

  // Build restoreActions map from planGroups (if provided) for mode lookups
  const restoreActions = planGroups
    ? new Map<string, RestoreMode>(
        planGroups
          .flatMap((g) => g.actions)
          .map((a) => [a.id, a.action as RestoreMode]),
      )
    : undefined;

  // Build nodeMap for quick lookup by objectId (used in plan-driven path)
  const nodeMap = new Map<string, BackupTreeNode>();
  for (const node of allNodes) {
    const id = getNodeObjectId(node);
    if (id) nodeMap.set(id, node);
  }

  const failures: { node: BackupTreeNode; error: string }[] = [];

  const findInactiveRefs = (refs: IObjectReference[]) =>
    findInactive(client, refs);

  const reportRemaining = (
    phaseName: string,
    stillInactive: IObjectReference[],
  ) => {
    logVerbose(
      1,
      `  [!] WARNING: ${phaseName}: ${stillInactive.length} object(s) remain inactive:`,
    );
    for (const ref of stillInactive) {
      logVerbose(1, `      - ${ref.type}:${ref.name}`);
    }
  };

  // Activate the refs that are inactive, wait for the run, then read the
  // inactive list again: that list, not the run's verdict, is what the
  // summary reports.
  const bulkActivate = async (phaseName: string, refs: IObjectReference[]) => {
    if (refs.length === 0) return;

    const toActivate = await findInactiveRefs(refs);
    if (toActivate.length === 0) {
      logVerbose(
        2,
        `  [*] ${phaseName}: all ${refs.length} objects already active`,
      );
      return;
    }

    logVerbose(
      2,
      `  [*] Bulk activating ${phaseName} (${toActivate.length}/${refs.length} inactive)...`,
    );
    const outcome = await activateGroup(client, toActivate);
    for (const message of outcome.messages) {
      logVerbose(outcome.ok ? 2 : 1, `    ${message}`);
    }

    const stillInactive = await findInactiveRefs(refs);
    if (stillInactive.length === 0) {
      logVerbose(2, `  [*] ${phaseName}: all objects activated successfully`);
    } else {
      reportRemaining(phaseName, stillInactive);
    }
  };

  // Helper: process a single node (create/update)
  const processNode = async (
    node: BackupTreeNode,
    activateFlag: boolean,
  ): Promise<IObjectReference | null> => {
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
      await writeObject(target, node, {
        mode: nodeMode,
        activate: activateFlag,
        transportRequest,
        softwareComponent,
        backupPackageNames,
        transportLayer,
      });
      if (shouldActivate && node.adtType && isActivatable(node.type)) {
        return objectReference({
          name: node.name,
          adtType: node.adtType,
          functionGroupName: node.functionGroupName,
        });
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (error instanceof AdtCallError && error.status === 403) {
        // Refused, typically for want of authorization on this type — or a
        // lock another session holds; SAP's text says which.
        logVerbose(1, `  [SKIP] ${node.type}:${node.name} — ${message}`);
      } else {
        logVerbose(1, `  [FAIL] ${node.type}:${node.name} — ${message}`);
        failures.push({ node, error: message });
      }
    }
    return null;
  };

  // Phase 1: Packages (recursive hierarchy) — shared by both paths
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
            await writeObject(target, node, {
              mode: effectiveMode,
              activate: false,
              transportRequest,
              softwareComponent,
              backupPackageNames,
              superPackage: parentName || superPackageOverride,
              transportLayer,
            });
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

  const allProcessedRefs: IObjectReference[] = [];

  if (planGroups) {
    // ===== Plan-driven restore: follow plan group order =====
    logVerbose(1, `\n>>> PLAN-DRIVEN RESTORE: ${planGroups.length} groups`);

    for (const group of planGroups) {
      const nonPackageActions = group.actions.filter(
        (a) => a.type !== 'package',
      );
      if (nonPackageActions.length === 0) continue;

      logVerbose(
        1,
        `[GROUP ${group.id}] ${nonPackageActions.length} object(s)${group.isCircular ? ' (circular)' : ''}`,
      );

      const groupRefs: IObjectReference[] = [];
      for (const action of nonPackageActions) {
        if (action.action === 'skip') {
          logVerbose(2, `  [SKIP] ${action.type}:${action.name}`);
          continue;
        }

        const node = nodeMap.get(action.id);
        if (!node) {
          logVerbose(1, `  [WARN] Node not found for ${action.id}, skipping`);
          continue;
        }

        const ref = await processNode(node, false);
        if (ref) groupRefs.push(ref);
      }

      if (groupRefs.length > 0) {
        await bulkActivate(
          `Group ${group.id}${group.isCircular ? ' (circular)' : ''}`,
          groupRefs,
        );
      }
      allProcessedRefs.push(...groupRefs);
    }
  } else {
    // ===== Fallback: type-phase restore (no plan) =====
    logVerbose(1, `\n>>> STARTING TYPE-PHASE RESTORE: ${nodes.length} objects`);

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

    const knownTypes = new Set<SupportedType>(
      RESTORE_PHASES.flatMap((p) => p.types),
    );
    const uncategorizedNodes = orderedNodes.filter(
      (n) => n.type && !knownTypes.has(n.type) && n.type !== 'package',
    );

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
        for (const node of phaseNodes) {
          const ref = await processNode(node, true);
          if (ref) allProcessedRefs.push(ref);
        }
      } else if (phase.activation === 'bulk') {
        const refs: IObjectReference[] = [];
        for (const node of phaseNodes) {
          const ref = await processNode(node, false);
          if (ref) refs.push(ref);
        }
        await bulkActivate(phase.name, refs);
        allProcessedRefs.push(...refs);
      } else if (phase.activation === 'cluster') {
        const groups = analyzeDependencies(phaseNodes);
        logVerbose(2, `  Dependency clustering: ${groups.length} cluster(s)`);
        for (let gi = 0; gi < groups.length; gi++) {
          const group = groups[gi];
          const clusterRefs: IObjectReference[] = [];
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
  }

  // Final check: find remaining inactive objects and activate them. Only the
  // objects that were processed are checked — a failed one is in `failures`,
  // so "all active" below never speaks for it.
  let inactiveLeft = 0;
  if (allProcessedRefs.length > 0) {
    const stillInactive = await findInactiveRefs(allProcessedRefs);
    if (stillInactive.length > 0) {
      logVerbose(
        1,
        `[FINAL] ${stillInactive.length} object(s) still inactive, activating...`,
      );
      const outcome = await activateGroup(client, stillInactive);
      for (const message of outcome.messages) {
        logVerbose(outcome.ok ? 2 : 1, `    ${message}`);
      }

      // Verify final state
      const remaining = await findInactiveRefs(allProcessedRefs);
      inactiveLeft = remaining.length;
      if (remaining.length > 0) {
        logVerbose(1, `  [!] ${remaining.length} object(s) remain inactive:`);
        for (const ref of remaining) {
          logVerbose(1, `      - ${ref.type}:${ref.name}`);
        }
      } else {
        logVerbose(
          1,
          failures.length > 0
            ? '[FINAL] All processed objects activated; the failed ones below were not processed.'
            : '[FINAL] All objects activated successfully.',
        );
      }
    } else {
      logVerbose(
        1,
        failures.length > 0
          ? '[FINAL] All processed objects are active; the failed ones below were not processed.'
          : '[FINAL] All objects are active.',
      );
    }
  }

  if (failures.length > 0) {
    logVerbose(
      1,
      `\n>>> RESTORE COMPLETED WITH ${failures.length} FAILURE(S):`,
    );
    for (const f of failures) {
      logVerbose(1, `  - ${f.node.type}:${f.node.name}: ${f.error}`);
    }
  } else if (inactiveLeft > 0) {
    logVerbose(
      1,
      `\n>>> RESTORE COMPLETED WITH ${inactiveLeft} OBJECT(S) INACTIVE.`,
    );
  } else {
    logVerbose(1, '\n>>> RESTORE COMPLETED SUCCESSFULLY.');
  }
  return { failed: failures.length, inactive: inactiveLeft };
}
