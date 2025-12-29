import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import { logVerbose } from '../cli/logVerbose';
import type { BackupObject, RestoreMode } from '../types';
import { restoreObject } from './restoreObject';
import { sortByDependencies } from './sortByDependencies';

export async function restoreObjects(
  client: AdtClient,
  objects: BackupObject[],
  mode: RestoreMode,
  activateOnUpdate: boolean,
  transportRequest?: string,
  restoreActions?: Map<string, RestoreMode>,
  activateOnCreate = true,
): Promise<void> {
  const ordered = sortByDependencies(objects);
  logVerbose(
    2,
    `Restoring ${ordered.length} object(s) in flat mode (mode=${mode}, activate=${activateOnUpdate})`,
  );
  for (const obj of ordered) {
    logVerbose(3, `Restore ${obj.type}:${obj.name}`);
    const nodeMode =
      mode === 'upsert' && restoreActions?.has(obj.id)
        ? restoreActions.get(obj.id)
        : mode;
    const effectiveActivate =
      nodeMode === 'create' ? activateOnCreate : activateOnUpdate;
    if (nodeMode === 'upsert') {
      try {
        await restoreObject(
          client,
          obj,
          'create',
          effectiveActivate,
          transportRequest,
        );
      } catch (_error) {
        await restoreObject(
          client,
          obj,
          'update',
          effectiveActivate,
          transportRequest,
        );
      }
    } else {
      await restoreObject(
        client,
        obj,
        nodeMode || mode,
        effectiveActivate,
        transportRequest,
      );
    }
  }
}
