import type { AdtClient, ObjectReference } from '@mcp-abap-adt/adt-clients';
import { XMLParser } from 'fast-xml-parser';
import { logVerbose } from '../cli/logVerbose';
import { flattenTree } from '../tree/flattenTree';
import { getNodeObjectId } from '../tree/getNodeObjectId';
import type {
  BackupTreeNode,
  RestoreMode,
  RestorePlanGroup,
  SupportedType,
} from '../types';
import { analyzeDependencies } from './analyzeDependencies';
import { restoreTreeNode } from './restoreTreeNode';

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  parseAttributeValue: false,
});

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

export async function restoreTreeBackup(
  client: AdtClient,
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

  // Helper: check which of our refs are still inactive
  const findInactiveRefs = async (
    refs: ObjectReference[],
  ): Promise<ObjectReference[]> => {
    const result = await client.getUtils().getInactiveObjects();
    const inactiveSet = new Set(
      result.objects.map((o) => `${o.type}:${o.name}`.toUpperCase()),
    );
    return refs.filter((r) =>
      inactiveSet.has(`${r.type}:${r.name}`.toUpperCase()),
    );
  };

  // Helper to bulk activate a list of refs with verification
  const bulkActivate = async (phaseName: string, refs: ObjectReference[]) => {
    if (refs.length === 0) return;

    // Check which objects are actually inactive
    let toActivate = await findInactiveRefs(refs);
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

    let hasErrors = false;
    try {
      const result = await client
        .getUtils()
        .activateObjectsGroup(toActivate, true);
      if (result?.data) {
        const parsed = xmlParser.parse(
          typeof result.data === 'string' ? result.data : String(result.data),
        );
        const msgs = parsed?.['chkl:messages']?.msg;
        if (msgs) {
          const msgArray = Array.isArray(msgs) ? msgs : [msgs];
          for (const msg of msgArray) {
            const type = msg['@_type'] || 'info';
            const text = msg?.shortText?.txt || msg?.shortText || String(msg);
            if (type === 'E') hasErrors = true;
            logVerbose(2, `    [${type}] ${text}`);
          }
        }
      }
    } catch (error) {
      hasErrors = true;
      const message = error instanceof Error ? error.message : String(error);
      logVerbose(2, `  [*] Activation request completed (${message})`);
    }

    // Verify: poll until our objects are no longer inactive (max 5 retries, 10s apart)
    // Skip polling if activation returned errors
    if (hasErrors) {
      const stillInactive = await findInactiveRefs(refs);
      if (stillInactive.length > 0) {
        logVerbose(
          1,
          `  [!] WARNING: ${phaseName}: ${stillInactive.length} object(s) remain inactive:`,
        );
        for (const ref of stillInactive) {
          logVerbose(1, `      - ${ref.type}:${ref.name}`);
        }
      }
      return;
    }
    const maxRetries = 5;
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      const stillInactive = await findInactiveRefs(refs);
      if (stillInactive.length === 0) {
        logVerbose(2, `  [*] ${phaseName}: all objects activated successfully`);
        return;
      }
      if (attempt < maxRetries) {
        logVerbose(
          2,
          `  [*] ${stillInactive.length} object(s) still inactive, waiting... (${attempt}/${maxRetries})`,
        );
        await new Promise((resolve) => setTimeout(resolve, 10000));
      } else {
        logVerbose(
          1,
          `  [!] WARNING: ${phaseName}: ${stillInactive.length} object(s) remain inactive:`,
        );
        for (const ref of stillInactive) {
          logVerbose(1, `      - ${ref.type}:${ref.name}`);
        }
      }
    }
  };

  // Helper: process a single node (create/update)
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

  const allProcessedRefs: ObjectReference[] = [];

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

      const groupRefs: ObjectReference[] = [];
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
        const refs: ObjectReference[] = [];
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

  // Final check: find remaining inactive objects and activate them
  if (allProcessedRefs.length > 0) {
    const stillInactive = await findInactiveRefs(allProcessedRefs);
    if (stillInactive.length > 0) {
      logVerbose(
        1,
        `[FINAL] ${stillInactive.length} object(s) still inactive, activating...`,
      );
      try {
        await client.getUtils().activateObjectsGroup(stillInactive, true);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        logVerbose(2, `  [*] Final activation request completed (${message})`);
      }

      // Verify final state
      const remaining = await findInactiveRefs(allProcessedRefs);
      if (remaining.length > 0) {
        logVerbose(1, `  [!] ${remaining.length} object(s) remain inactive:`);
        for (const ref of remaining) {
          logVerbose(1, `      - ${ref.type}:${ref.name}`);
        }
      } else {
        logVerbose(1, '[FINAL] All objects activated successfully.');
      }
    } else {
      logVerbose(1, '[FINAL] All objects are active.');
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
  } else {
    logVerbose(1, '\n>>> RESTORE COMPLETED SUCCESSFULLY.');
  }
}
