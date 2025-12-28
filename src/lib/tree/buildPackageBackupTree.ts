import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import type { BackupTreeFile } from '../types';
import { buildPackageBackupTreeFromVirtualFolders } from './buildPackageBackupTreeFromVirtualFolders';

export async function buildPackageBackupTree(
  client: AdtClient,
  packageName: string,
  includeCode: boolean,
): Promise<BackupTreeFile> {
  return buildPackageBackupTreeFromVirtualFolders(
    client,
    packageName,
    includeCode,
  );
}
