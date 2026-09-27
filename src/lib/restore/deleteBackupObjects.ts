import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import { analyseDeletion } from '@mcp-abap-adt/adt-strategies';
import { AdtCallError } from '../adt/answer';
import type { BackupTreeFile } from '../types';
import { collectDeletionTargets } from './collectDeletionTargets';

/**
 * Delete every object of a backup tree from the target, as one group.
 *
 * The deletion check first, then the delete, both judged by
 * `analyseDeletion`: SAP refuses inside a `200` (`isDeletable="false"`,
 * `isDeleted="false"`, or an `E` message), and since adt-clients 23 nothing
 * reads that verdict unless the caller asks.
 */
export async function deleteBackupObjects(
  client: AdtClient,
  backup: BackupTreeFile,
  transportRequest?: string,
): Promise<void> {
  const targets = collectDeletionTargets(backup.root);
  if (targets.length === 0) {
    return;
  }
  const utils = client.getUtils();

  const checked = await utils.checkDeletionGroup(targets, {
    analyse: analyseDeletion,
  });
  if (!checked.ok) {
    throw new AdtCallError(
      'Deletion check failed before cleanup',
      checked.getError(),
    );
  }

  const deleted = await utils.deleteObjectsGroup(
    targets,
    transportRequest?.trim() || undefined,
    { analyse: analyseDeletion },
  );
  if (!deleted.ok) {
    throw new AdtCallError('Group deletion refused', deleted.getError());
  }
}
