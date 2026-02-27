import type { AdtClient, ObjectReference } from '@mcp-abap-adt/adt-clients';
import { logVerbose } from '../cli/logVerbose';
import type { BackupObject, RestoreMode } from '../types';
import { verifyObjectInSystem } from '../verify/verifyObjectInSystem';
import { restoreObject } from './restoreObject';
import { sortByDependencies } from './sortByDependencies';

const ADT_TYPE_MAP: Partial<Record<string, string>> = {
  package: 'DEVC/K',
  domain: 'DOMA/DT',
  dataElement: 'DTEL/DE',
  structure: 'TABL/DT',
  table: 'TABL/DT',
  tableType: 'TTYP/DT',
  view: 'VIEW/DV',
  class: 'CLAS/OC',
  interface: 'INTF/OI',
  program: 'PROG/P',
  functionGroup: 'FUGR/FF',
  functionModule: 'FUGR/I',
  serviceDefinition: 'SRVD/SRV',
  serviceBinding: 'SRVB/SRV',
  metadataExtension: 'DDLX/PX',
  behaviorDefinition: 'BDEF/B',
  behaviorImplementation: 'CLAS/OC',
  enhancement: 'ENHO/EI',
  accessControl: 'DCLS/DL',
};

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
  const activationList: ObjectReference[] = [];

  for (const obj of ordered) {
    logVerbose(3, `Restore ${obj.type}:${obj.name}`);
    let nodeMode =
      mode === 'upsert' && restoreActions?.has(obj.id)
        ? restoreActions.get(obj.id)
        : mode;

    if (nodeMode === 'upsert') {
      const verifyResult = await verifyObjectInSystem(client, {
        type: obj.type,
        name: obj.name,
        functionGroupName: obj.functionGroupName,
      });
      nodeMode = verifyResult.status === 'missing' ? 'create' : 'update';
    }

    const isPackage = obj.type === 'package';
    const shouldActivate =
      nodeMode === 'create' ? activateOnCreate : activateOnUpdate;
    // Defer activation for non-package objects
    const effectiveActivate = isPackage ? shouldActivate : false;

    await restoreObject(
      client,
      obj,
      nodeMode || mode,
      effectiveActivate,
      transportRequest,
    );

    if (!isPackage && shouldActivate && ADT_TYPE_MAP[obj.type]) {
      activationList.push({ name: obj.name, type: ADT_TYPE_MAP[obj.type]! });
    }
  }

  if (activationList.length > 0) {
    logVerbose(2, `Activating ${activationList.length} object(s) in group...`);
    try {
      await client.getUtils().activateObjectsGroup(activationList, true);
      logVerbose(2, 'Group activation completed successfully.');
    } catch (error) {
      logVerbose(
        1,
        'Group activation failed (this is common due to complex dependencies).',
      );
      logVerbose(
        1,
        `Error: ${error instanceof Error ? error.message : String(error)}`,
      );
      logVerbose(
        1,
        'Objects are restored but might remain inactive. Please check and activate them manually in ADT.',
      );
    }
  }
}
