import { decodeBase64 } from '../crypto/decodeBase64';
import type { BackupTreeNode } from '../types';

export interface RestoreGroup {
  nodes: BackupTreeNode[];
  isCircular: boolean;
}

function nodeKey(node: BackupTreeNode): string {
  return `${node.type}:${node.name}`.toUpperCase();
}

/**
 * Build adjacency map (forward dependencies) by scanning source code and config.
 */
function buildAdjacency(
  nodes: BackupTreeNode[],
  allNames: Set<string>,
  nameToIds: Map<string, string[]>,
  allIds: Set<string>,
): Map<string, Set<string>> {
  const adj = new Map<string, Set<string>>();

  for (const node of nodes) {
    const deps = new Set<string>();
    const id = nodeKey(node);
    const nodeNameUpper = node.name.toUpperCase();

    if (node.codeBase64) {
      const decoded = decodeBase64(node.codeBase64);
      const contentUpper = decoded.toUpperCase();

      // 1. Scan for all backup object names in the content
      for (const targetName of allNames) {
        if (targetName === nodeNameUpper) continue;

        const escapedTarget = targetName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const regex = new RegExp(
          `(?<=[^A-Z0-9_/]|^)${escapedTarget}(?=[^A-Z0-9_/]|$)`,
          'g',
        );

        if (regex.test(contentUpper)) {
          const targetIds = nameToIds.get(targetName) || [];
          for (const tid of targetIds) {
            if (tid !== id) deps.add(tid);
          }
        }
      }

      // 2. Explicit structural dependencies

      // BIML class -> BDEF (bidirectional = same SCC)
      if (node.type === 'class' || node.type === 'behaviorImplementation') {
        const bdefMatch = contentUpper.match(
          /FOR\s+BEHAVIOR\s+OF\s+([A-Z0-9_/]+)/,
        );
        if (bdefMatch) {
          const bdefId = `BEHAVIORDEFINITION:${bdefMatch[1]}`;
          if (allIds.has(bdefId) && bdefId !== id) deps.add(bdefId);
        }
      }

      // BDEF -> BIML class
      if (node.type === 'behaviorDefinition') {
        for (const m of contentUpper.matchAll(
          /IMPLEMENTATION\s+IN\s+CLASS\s+([A-Z0-9_/]+)/g,
        )) {
          const className = m[1];
          const classId = `CLASS:${className}`;
          if (allIds.has(classId)) deps.add(classId);
          const bimpId = `BEHAVIORIMPLEMENTATION:${className}`;
          if (allIds.has(bimpId)) deps.add(bimpId);
        }
      }

      // Behavior Implementation -> Behavior Definition (from config)
      if (
        node.type === 'behaviorImplementation' &&
        node.config?.behaviorDefinition
      ) {
        const bdef = String(node.config.behaviorDefinition).toUpperCase();
        const bdefId = `BEHAVIORDEFINITION:${bdef}`;
        if (allIds.has(bdefId)) deps.add(bdefId);
      }

      // Service Binding -> Service Definition
      if (
        node.type === 'serviceBinding' &&
        node.config?.serviceDefinitionName
      ) {
        const srvd = String(node.config.serviceDefinitionName).toUpperCase();
        const srvdId = `SERVICEDEFINITION:${srvd}`;
        if (allIds.has(srvdId)) deps.add(srvdId);
      }
    }

    adj.set(id, deps);
  }

  return adj;
}

/**
 * Tarjan's SCC algorithm.
 */
function tarjanSCC(
  allIds: Set<string>,
  adj: Map<string, Set<string>>,
): string[][] {
  let index = 0;
  const stack: string[] = [];
  const onStack = new Set<string>();
  const indices = new Map<string, number>();
  const lowlink = new Map<string, number>();
  const sccs: string[][] = [];

  function strongConnect(v: string) {
    indices.set(v, index);
    lowlink.set(v, index);
    index++;
    stack.push(v);
    onStack.add(v);

    const deps = adj.get(v) || new Set();
    for (const w of deps) {
      if (!indices.has(w)) {
        strongConnect(w);
        const lowV = lowlink.get(v);
        const lowW = lowlink.get(w);
        if (lowV !== undefined && lowW !== undefined) {
          lowlink.set(v, Math.min(lowV, lowW));
        }
      } else if (onStack.has(w)) {
        const lowV = lowlink.get(v);
        const idxW = indices.get(w);
        if (lowV !== undefined && idxW !== undefined) {
          lowlink.set(v, Math.min(lowV, idxW));
        }
      }
    }

    if (lowlink.get(v) === indices.get(v)) {
      const scc: string[] = [];
      let w: string;
      do {
        w = stack.pop() || '';
        onStack.delete(w);
        scc.push(w);
      } while (w !== v);
      sccs.push(scc);
    }
  }

  for (const id of allIds) {
    if (!indices.has(id)) {
      strongConnect(id);
    }
  }

  return sccs;
}

/**
 * Build SCC DAG and topological order from SCCs and adjacency map.
 */
function buildSccDag(
  sccs: string[][],
  adj: Map<string, Set<string>>,
): { sccAdj: Map<number, Set<number>>; order: number[] } {
  const sccAdj = new Map<number, Set<number>>();
  const nodeToSccIndex = new Map<string, number>();
  sccs.forEach((scc, i) => {
    for (const id of scc) {
      nodeToSccIndex.set(id, i);
    }
  });

  sccs.forEach((scc, i) => {
    const deps = new Set<number>();
    for (const id of scc) {
      const nodeDeps = adj.get(id) || new Set();
      for (const depId of nodeDeps) {
        const depSccIndex = nodeToSccIndex.get(depId);
        if (depSccIndex !== undefined && depSccIndex !== i) {
          deps.add(depSccIndex);
        }
      }
    }
    sccAdj.set(i, deps);
  });

  // Topological sort
  const visited = new Set<number>();
  const order: number[] = [];

  function visit(i: number) {
    if (visited.has(i)) return;
    visited.add(i);
    const deps = sccAdj.get(i) || new Set();
    for (const d of deps) {
      visit(d);
    }
    order.push(i);
  }

  for (let i = 0; i < sccs.length; i++) {
    visit(i);
  }

  return { sccAdj, order };
}

/**
 * Robustly analyzes dependencies between objects by scanning both
 * source code and XML metadata.
 * Uses composite type:name keys to handle objects that share the same name
 * (e.g. view and behaviorDefinition for the same CDS entity).
 */
export function analyzeDependencies(nodes: BackupTreeNode[]): RestoreGroup[] {
  const idToNode = new Map<string, BackupTreeNode>();
  const nameToIds = new Map<string, string[]>();
  const allNames = new Set<string>();

  for (const node of nodes) {
    const id = nodeKey(node);
    const upperName = node.name.toUpperCase();
    idToNode.set(id, node);
    allNames.add(upperName);
    const ids = nameToIds.get(upperName) || [];
    ids.push(id);
    nameToIds.set(upperName, ids);
  }

  const allIds = new Set(idToNode.keys());
  const adj = buildAdjacency(nodes, allNames, nameToIds, allIds);
  const sccs = tarjanSCC(allIds, adj);
  const { order } = buildSccDag(sccs, adj);

  return order.map((i) => {
    const ids = sccs[i];
    return {
      nodes: ids.map((id) => idToNode.get(id)!),
      isCircular: ids.length > 1,
    };
  });
}

/**
 * Creation order priority within a group.
 * Lower = created first. Ensures BDEF exists before BIML class, etc.
 */
const TYPE_CREATION_ORDER: Record<string, number> = {
  domain: 0,
  dataElement: 1,
  structure: 2,
  table: 2,
  tableType: 2,
  ddl: 3,
  scalarFunction: 3,
  behaviorDefinition: 4,
  behaviorImplementation: 5,
  class: 5,
  scalarFunctionImplementation: 6,
  interface: 5,
  accessControl: 6,
  metadataExtension: 6,
  program: 7,
  transformation: 7,
  functionGroup: 7,
  functionInclude: 8,
  functionModule: 9,
  serviceDefinition: 10,
  serviceBinding: 11,
  enhancement: 12,
};

/**
 * Analyzes dependencies and merges SCCs at the same dependency level
 * into single groups. Level = max(level of dependencies) + 1.
 * Independent SCCs (same level) are merged into one group.
 */
export function analyzeDependencyLevels(
  nodes: BackupTreeNode[],
): RestoreGroup[] {
  const idToNode = new Map<string, BackupTreeNode>();
  const nameToIds = new Map<string, string[]>();
  const allNames = new Set<string>();

  for (const node of nodes) {
    const id = nodeKey(node);
    const upperName = node.name.toUpperCase();
    idToNode.set(id, node);
    allNames.add(upperName);
    const ids = nameToIds.get(upperName) || [];
    ids.push(id);
    nameToIds.set(upperName, ids);
  }

  const allIds = new Set(idToNode.keys());
  const adj = buildAdjacency(nodes, allNames, nameToIds, allIds);
  const sccs = tarjanSCC(allIds, adj);
  const { sccAdj, order } = buildSccDag(sccs, adj);

  // Compute level for each SCC: level = max(level of deps) + 1
  const sccLevel = new Map<number, number>();
  for (const i of order) {
    let maxDepLevel = -1;
    const deps = sccAdj.get(i) || new Set();
    for (const d of deps) {
      const depLevel = sccLevel.get(d) ?? 0;
      if (depLevel > maxDepLevel) maxDepLevel = depLevel;
    }
    sccLevel.set(i, maxDepLevel + 1);
  }

  // Group SCCs by level, merge into RestoreGroups
  const levelMap = new Map<
    number,
    { nodes: BackupTreeNode[]; hasCircular: boolean }
  >();
  for (const i of order) {
    const level = sccLevel.get(i)!;
    if (!levelMap.has(level)) {
      levelMap.set(level, { nodes: [], hasCircular: false });
    }
    const entry = levelMap.get(level)!;
    const sccNodes = sccs[i].map((id) => idToNode.get(id)!);
    entry.nodes.push(...sccNodes);
    if (sccs[i].length > 1) entry.hasCircular = true;
  }

  const sortedLevels = [...levelMap.keys()].sort((a, b) => a - b);
  return sortedLevels.map((level) => {
    const entry = levelMap.get(level)!;
    // Sort nodes within group by creation order (views before BDEFs before classes)
    entry.nodes.sort(
      (a, b) =>
        (TYPE_CREATION_ORDER[a.type || ''] ?? 99) -
        (TYPE_CREATION_ORDER[b.type || ''] ?? 99),
    );
    return {
      nodes: entry.nodes,
      isCircular: entry.hasCircular || entry.nodes.length > 1,
    };
  });
}
