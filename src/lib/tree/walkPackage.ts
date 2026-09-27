import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import {
  analyseException,
  readNodeStructure,
} from '@mcp-abap-adt/adt-strategies';
import { requireOk, textOf } from '../adt/answer';
import { readMetadataXmlForType } from '../backup/readMetadataXmlForType';
import { logVerbose } from '../cli/logVerbose';
import type { BackupTreeNode } from '../types';
import { extractMetadata } from '../xml/extractMetadata';

/*
 * Ported from @mcp-abap-adt/adt-clients (scripts/lib/packageWalk.ts,
 * `walkPackage`, at fb61b9b6). adt-clients removed `getPackageHierarchy` in
 * 19.0.0: a walk is one node-structure request per object type plus a descent
 * into subpackages, and that sequence is the consumer's. Changes from the
 * original: it goes through the public `getUtils().fetchNodeStructure`, it
 * descends without a depth limit (a backup takes the whole package), it guards
 * against a package reached twice, and it answers the backup's tree node.
 */

const isPackageType = (type: string): boolean =>
  type === 'DEVC/K' || type.startsWith('DEVC');

const field = (node: Record<string, unknown>, key: string): string => {
  const value = node[key];
  if (typeof value === 'string' || typeof value === 'number') {
    return String(value);
  }
  if (value && typeof value === 'object') {
    const text = (value as Record<string, unknown>)['#text'];
    if (typeof text === 'string' || typeof text === 'number') {
      return String(text);
    }
  }
  return '';
};

/** The node structure of one parent, read into its two halves. */
async function nodeStructure(
  client: AdtClient,
  parentType: string,
  parentName: string,
  nodeId?: string,
): Promise<ReturnType<typeof readNodeStructure>> {
  const answer = await client
    .getUtils()
    .fetchNodeStructure(parentType, parentName, {
      nodeId,
      withShortDescriptions: true,
      analyse: analyseException,
    });
  const xml = textOf(
    requireOk(answer, `read node structure of ${parentType} ${parentName}`),
  );
  return readNodeStructure(xml);
}

/**
 * One package level and everything below it.
 *
 * **An empty body is a level with nothing in it, and nothing more than that.**
 * `/repository/nodestructure` answers `200` with zero bytes for an existing
 * but empty package and for a name that was never created alike, so this walk
 * states neither and descends no further. Whether the root exists is asked
 * separately (see {@link walkPackageTree}), of `/packages/{name}`, which
 * answers `404` for a name that was never created.
 */
async function walkLevel(
  client: AdtClient,
  packageName: string,
  description: string | undefined,
  visited: Set<string>,
): Promise<BackupTreeNode> {
  const name = packageName.toUpperCase();
  visited.add(name);
  const level: BackupTreeNode = { name, adtType: 'DEVC/K' };
  if (description) level.description = description;

  const { nodes, objectTypes } = await nodeStructure(client, 'DEVC/K', name);
  if (nodes.length === 0 && objectTypes.length === 0) {
    logVerbose(3, `  Package ${name}: node structure is empty`);
    return level;
  }

  const all = [...nodes];
  for (const typeInfo of objectTypes) {
    if (isPackageType(typeInfo.objectType)) continue;
    const perType = await nodeStructure(
      client,
      'DEVC/K',
      name,
      typeInfo.nodeId,
    );
    all.push(...perType.nodes);
  }

  const children: BackupTreeNode[] = [];
  const seen = new Set<string>();
  for (const node of all) {
    const type = field(node, 'OBJECT_TYPE');
    const childName = field(node, 'OBJECT_NAME');
    if (!childName) continue;
    const key = `${type}:${childName.toUpperCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const childDescription = field(node, 'DESCRIPTION') || undefined;
    if (isPackageType(type)) {
      if (visited.has(childName.toUpperCase())) continue;
      children.push(
        await walkLevel(client, childName, childDescription, visited),
      );
    } else {
      const child: BackupTreeNode = { name: childName, adtType: type };
      if (childDescription) child.description = childDescription;
      children.push(child);
    }
  }

  if (children.length > 0) level.children = children;
  return level;
}

/**
 * The package hierarchy the backup starts from: the package, its objects and
 * its subpackages, recursively.
 *
 * The root is asked about first: a node structure cannot tell a missing
 * package from an empty one, `/packages/{name}` can.
 */
export async function walkPackageTree(
  client: AdtClient,
  packageName: string,
): Promise<BackupTreeNode> {
  const name = packageName.toUpperCase();
  const metadata = await readMetadataXmlForType(client, 'package', name);
  if (!metadata) {
    throw new Error(`Package not found: ${name}`);
  }
  const { description } = extractMetadata(metadata);
  return walkLevel(client, name, description, new Set<string>());
}
