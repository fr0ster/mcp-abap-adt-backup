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

        // Escape name for regex, specifically handling namespaces with /
        const escapedTarget = targetName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

        // Match only if surrounded by boundaries that are NOT part of an ABAP name
        // (i.e. not letters, digits, _, or /)
        const regex = new RegExp(
          `(?<=[^A-Z0-9_/]|^)${escapedTarget}(?=[^A-Z0-9_/]|$)`,
          'g',
        );

        if (regex.test(contentUpper)) {
          // Resolve name to all node IDs with that name
          const targetIds = nameToIds.get(targetName) || [];
          for (const tid of targetIds) {
            if (tid !== id) deps.add(tid);
          }
        }
      }

      // 2. Explicit structural dependencies (from config or XML properties)
      // Example: Behavior Implementation -> Behavior Definition
      if (
        node.type === 'behaviorImplementation' &&
        node.config?.behaviorDefinition
      ) {
        const bdef = String(node.config.behaviorDefinition).toUpperCase();
        const bdefId = `BEHAVIORDEFINITION:${bdef}`;
        if (allIds.has(bdefId)) deps.add(bdefId);
      }

      // Example: Service Binding -> Service Definition
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

  // Tarjan's algorithm for SCCs
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

  // Dependency graph of SCCs
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

  return order.map((i) => {
    const ids = sccs[i];
    return {
      nodes: ids.map((id) => idToNode.get(id)!),
      isCircular: ids.length > 1,
    };
  });
}
