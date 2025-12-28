import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import type { BackupTreeFile } from '../types';
import { collectDeletionTargets } from './collectDeletionTargets';

export async function deleteBackupObjects(
  client: AdtClient,
  backup: BackupTreeFile,
  transportRequest?: string,
): Promise<void> {
  const targets = collectDeletionTargets(backup.root);
  if (targets.length === 0) {
    return;
  }

  await client.getUtils().checkDeletionGroup(targets);
  await client
    .getUtils()
    .deleteObjectsGroup(targets, transportRequest?.trim() || undefined);
}
