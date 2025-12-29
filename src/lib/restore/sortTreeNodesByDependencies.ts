import { typeOrder } from '../constants/typeOrder';
import { getNodeObjectId } from '../tree/getNodeObjectId';
import type { BackupTreeNode } from '../types';
import { objectId } from '../utils/objectId';
import { parseObjectSpec } from '../utils/parseObjectSpec';

export function sortTreeNodesByDependencies(
  nodes: BackupTreeNode[],
): BackupTreeNode[] {
  const idToNode = new Map<string, BackupTreeNode>();
  for (const node of nodes) {
    const id = getNodeObjectId(node);
    if (id) {
      idToNode.set(id, node);
    }
  }

  const dependencies = new Map<string, Set<string>>();
  for (const id of idToNode.keys()) {
    dependencies.set(id, new Set());
  }

  for (const node of nodes) {
    const currentId = getNodeObjectId(node);
    if (!currentId || !node.usedBy) {
      continue;
    }
    for (const usedBySpec of node.usedBy) {
      let usedById: string;
      try {
        const spec = parseObjectSpec(usedBySpec);
        usedById = objectId(spec);
      } catch {
        continue;
      }
      if (!idToNode.has(usedById) || usedById === currentId) {
        continue;
      }
      const deps = dependencies.get(usedById);
      if (deps) {
        deps.add(currentId);
      }
    }
  }

  const indegree = new Map<string, number>();
  for (const [id, deps] of dependencies.entries()) {
    indegree.set(id, deps.size);
  }

  const priority = new Map(typeOrder.map((type, index) => [type, index]));
  const queue = Array.from(idToNode.entries())
    .filter(([id]) => (indegree.get(id) || 0) === 0)
    .sort(([, a], [, b]) => {
      const aOrder = a.type ? (priority.get(a.type) ?? 999) : 999;
      const bOrder = b.type ? (priority.get(b.type) ?? 999) : 999;
      return aOrder - bOrder || a.name.localeCompare(b.name);
    })
    .map(([id]) => id);

  const result: BackupTreeNode[] = [];
  const visited = new Set<string>();

  while (queue.length > 0) {
    const id = queue.shift();
    if (!id) {
      continue;
    }
    const node = idToNode.get(id);
    if (!node || visited.has(id)) {
      continue;
    }
    visited.add(id);
    result.push(node);

    for (const [otherId, deps] of dependencies.entries()) {
      if (!deps.has(id)) {
        continue;
      }
      deps.delete(id);
      const nextIndegree = (indegree.get(otherId) || 0) - 1;
      indegree.set(otherId, nextIndegree);
      if (nextIndegree === 0) {
        queue.push(otherId);
        queue.sort((aId, bId) => {
          const aNode = idToNode.get(aId);
          const bNode = idToNode.get(bId);
          const aOrder = aNode?.type ? (priority.get(aNode.type) ?? 999) : 999;
          const bOrder = bNode?.type ? (priority.get(bNode.type) ?? 999) : 999;
          return aOrder - bOrder || aId.localeCompare(bId);
        });
      }
    }
  }

  if (result.length !== nodes.length) {
    const remaining = nodes.filter((node) => {
      const id = getNodeObjectId(node);
      return id ? !visited.has(id) : true;
    });
    remaining.sort((a, b) => {
      const aOrder = a.type ? (priority.get(a.type) ?? 999) : 999;
      const bOrder = b.type ? (priority.get(b.type) ?? 999) : 999;
      return aOrder - bOrder || a.name.localeCompare(b.name);
    });
    result.push(...remaining);
  }

  return result;
}
