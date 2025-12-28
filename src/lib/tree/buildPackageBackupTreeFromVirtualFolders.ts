import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import { logVerbose } from '../cli/logVerbose';
import type { BackupTreeFile, BackupTreeNode } from '../types';
import { enrichTreeNode } from './enrichTreeNode';

export async function buildPackageBackupTreeFromVirtualFolders(
  client: AdtClient,
  packageName: string,
  includeCode: boolean,
): Promise<BackupTreeFile> {
  const packageNameUpper = packageName.toUpperCase();
  logVerbose(2, `Fetching package hierarchy for ${packageNameUpper}`);
  const hierarchy = await client
    .getUtils()
    .getPackageHierarchy(packageNameUpper);
  const rootTree: BackupTreeNode = {
    ...hierarchy,
    restoreStatus: 'not-implemented',
  };

  logVerbose(2, `Building node tree for ${packageNameUpper}`);
  const enrichedRoot = await enrichTreeNode(rootTree, client, includeCode);
  const finalRoot = enrichedRoot;

  return {
    schemaVersion: 2,
    generatedAt: new Date().toISOString(),
    package: packageNameUpper,
    root: finalRoot,
  };
}
