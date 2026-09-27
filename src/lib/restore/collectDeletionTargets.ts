import type { IObjectReference } from '@mcp-abap-adt/interfaces-adt';
import type { BackupTreeNode } from '../types';
import { objectReference } from './objectReference';

/**
 * Every object in the tree this tool restores — packages aside — once, as a
 * reference group deletion takes. A function module or include carries its
 * group as `parentName`: adt-clients addresses it under the group and refuses
 * one without it.
 *
 * **Only what the tool restores.** A package walk also lists what the system
 * generated for a published service binding — `G4BA`, `SCO2`, `SUSH` — and
 * those have no ADT address: a deletion check over them answers "No
 * URI-Mapping defined for URI" inside its 200, and the whole group is refused.
 * They go with their binding. A node the tool does not back up has no `type`,
 * and is left out.
 */
export function collectDeletionTargets(
  root: BackupTreeNode,
): IObjectReference[] {
  const targets: IObjectReference[] = [];
  const seen = new Set<string>();

  const visit = (node: BackupTreeNode): void => {
    if (node.type && node.adtType && node.adtType !== 'DEVC/K') {
      const key = `${node.adtType}:${node.name}`;
      if (!seen.has(key)) {
        seen.add(key);
        targets.push(
          objectReference({
            name: node.name,
            adtType: node.adtType,
            functionGroupName: node.functionGroupName,
          }),
        );
      }
    }
    if (node.children && node.children.length > 0) {
      for (const child of node.children) {
        visit(child);
      }
    }
  };

  visit(root);
  return targets;
}
