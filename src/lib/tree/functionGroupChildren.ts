import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import {
  analyseException,
  readNodeStructure,
} from '@mcp-abap-adt/adt-strategies';
import { requireOk, textOf } from '../adt/answer';

/*
 * Ported from @mcp-abap-adt/adt-clients (scripts/lib/functionGroupChildren.ts,
 * at fb61b9b6). adt-clients removed `listFunctionModules` and
 * `listFunctionGroupIncludes` in 19.0.0: each read the group's node structure,
 * found the child type's node id and read that node — two requests, which is
 * the consumer's sequence. Changed from the original only in going through the
 * public `getUtils().fetchNodeStructure`.
 */

/**
 * The names of a function group's children of one type.
 *
 * An empty node structure — `200` with zero bytes, what the endpoint answers
 * for a group with nothing under it and for one that is not there alike —
 * reads as no children. Deduped on the uppercased name, first occurrence
 * winning, because the node structure can list the same object twice under
 * different parents.
 */
export async function functionGroupChildren(
  client: AdtClient,
  functionGroupName: string,
  childType: 'FUGR/FF' | 'FUGR/I',
): Promise<string[]> {
  const name = functionGroupName.toUpperCase();
  const utils = client.getUtils();
  const what = `read node structure of FUGR/F ${name}`;

  const root = await utils.fetchNodeStructure('FUGR/F', name, {
    nodeId: '000000',
    withShortDescriptions: true,
    analyse: analyseException,
  });
  const { objectTypes } = readNodeStructure(textOf(requireOk(root, what)));

  const wanted = objectTypes.find((t) => t.objectType === childType);
  if (!wanted) return [];

  const children = await utils.fetchNodeStructure('FUGR/F', name, {
    nodeId: wanted.nodeId,
    withShortDescriptions: true,
    analyse: analyseException,
  });
  const { nodes } = readNodeStructure(textOf(requireOk(children, what)));

  const seen = new Set<string>();
  const names: string[] = [];
  for (const node of nodes) {
    const raw = node.OBJECT_NAME;
    const childName =
      typeof raw === 'string' || typeof raw === 'number' ? String(raw) : '';
    if (!childName) continue;
    const key = childName.toUpperCase();
    if (seen.has(key)) continue;
    seen.add(key);
    names.push(childName);
  }
  return names;
}
