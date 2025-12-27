import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import { logVerbose } from '../cli/logVerbose';
import type { BackupObject, RestoreMode } from '../types';
import { restoreObject } from './restoreObject';
import { sortByDependencies } from './sortByDependencies';

export async function restoreObjects(
  client: AdtClient,
  objects: BackupObject[],
  mode: RestoreMode,
  activate: boolean,
): Promise<void> {
  const ordered = sortByDependencies(objects);
  logVerbose(
    2,
    `Restoring ${ordered.length} object(s) in flat mode (mode=${mode}, activate=${activate})`,
  );
  for (const obj of ordered) {
    logVerbose(3, `Restore ${obj.type}:${obj.name}`);
    if (mode === 'upsert') {
      try {
        await restoreObject(client, obj, 'create', activate);
      } catch (_error) {
        await restoreObject(client, obj, 'update', activate);
      }
    } else {
      await restoreObject(client, obj, mode, activate);
    }
  }
}
