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

  const checkResponse = await client.getUtils().checkDeletionGroup(targets);
  const messages = checkResponse.data?.messages || [];
  const errors = messages.filter(
    (m: any) => m.severity === 'error' || m.severity === 'E',
  );

  if (errors.length > 0) {
    const errorList = errors
      .map((e: any) => `${e.objName}: ${e.text}`)
      .join('\n');
    throw new Error(`Deletion check failed before cleanup:\n${errorList}`);
  }

  await client
    .getUtils()
    .deleteObjectsGroup(targets, transportRequest?.trim() || undefined);
}
