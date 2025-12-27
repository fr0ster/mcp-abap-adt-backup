import { typeOrder } from '../constants/typeOrder';
import type { BackupObject } from '../types';

export function sortByDependencies(objects: BackupObject[]): BackupObject[] {
  const idToObject = new Map(objects.map((obj) => [obj.id, obj]));
  const dependencies = new Map<string, Set<string>>();
  const indegree = new Map<string, number>();

  for (const obj of objects) {
    const deps = new Set(
      (obj.dependsOn || []).filter((dep) => idToObject.has(dep)),
    );
    dependencies.set(obj.id, deps);
    indegree.set(obj.id, deps.size);
  }

  const priority = new Map(typeOrder.map((type, index) => [type, index]));

  const queue = objects
    .filter((obj) => (indegree.get(obj.id) || 0) === 0)
    .sort((a, b) => {
      const aOrder = priority.get(a.type) ?? 999;
      const bOrder = priority.get(b.type) ?? 999;
      return aOrder - bOrder || a.id.localeCompare(b.id);
    })
    .map((obj) => obj.id);

  const result: BackupObject[] = [];
  const visited = new Set<string>();

  while (queue.length > 0) {
    const id = queue.shift();
    if (!id) {
      continue;
    }
    const obj = idToObject.get(id);
    if (!obj || visited.has(id)) {
      continue;
    }
    visited.add(id);
    result.push(obj);

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
          const aObj = idToObject.get(aId);
          const bObj = idToObject.get(bId);
          const aOrder = aObj ? (priority.get(aObj.type) ?? 999) : 999;
          const bOrder = bObj ? (priority.get(bObj.type) ?? 999) : 999;
          return aOrder - bOrder || aId.localeCompare(bId);
        });
      }
    }
  }

  if (result.length !== objects.length) {
    const remaining = objects.filter((obj) => !visited.has(obj.id));
    remaining.sort((a, b) => {
      const aOrder = priority.get(a.type) ?? 999;
      const bOrder = priority.get(b.type) ?? 999;
      return aOrder - bOrder || a.id.localeCompare(b.id);
    });
    result.push(...remaining);
  }

  return result;
}
