import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import { logVerbose } from '../cli/logVerbose';
import { collectTreeDependencies } from '../dependencies/collectTreeDependencies';
import type { BackupTreeFile, BackupTreeNode, SupportedType } from '../types';
import { enrichTreeNode } from './enrichTreeNode';
import { flattenTree } from './flattenTree';

export async function buildPackageBackupTree(
  client: AdtClient,
  packageName: string,
): Promise<BackupTreeFile> {
  const packageNameUpper = packageName.toUpperCase();
  logVerbose(1, `Fetching package hierarchy for ${packageNameUpper}`);
  const hierarchy = await client
    .getUtils()
    .getPackageHierarchy(packageNameUpper);

  const rootTree: BackupTreeNode = {
    ...hierarchy,
    type: hierarchy.type as SupportedType | undefined,
    children: hierarchy.children as BackupTreeNode[] | undefined,
    restoreStatus: 'not-implemented',
  };

  logVerbose(1, `Enriching objects for ${packageNameUpper}`);
  const enrichedRoot = await enrichTreeNode(rootTree, client, true);

  const allNodes = flattenTree(enrichedRoot);
  const backed = allNodes.filter((n) => n.type && n.codeBase64);
  const skipped = allNodes.filter((n) => !n.type && n.adtType);
  const noPayload = allNodes.filter((n) => n.type && !n.codeBase64);
  logVerbose(
    1,
    `Summary: ${backed.length} backed up, ${skipped.length} unsupported, ${noPayload.length} without payload`,
  );

  logVerbose(1, `Collecting dependencies for ${packageNameUpper}`);
  await collectTreeDependencies(client, enrichedRoot);

  return {
    schemaVersion: 2,
    generatedAt: new Date().toISOString(),
    package: packageNameUpper,
    root: enrichedRoot,
  };
}
