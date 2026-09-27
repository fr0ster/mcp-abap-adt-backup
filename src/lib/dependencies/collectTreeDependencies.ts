import { type AdtClient, utilDocuments } from '@mcp-abap-adt/adt-clients';
import {
  analyseException,
  type IWhereUsedListResult,
  utilWhereUsedReferences,
} from '@mcp-abap-adt/adt-strategies';
import { isAbsence, requireOk, textOf } from '../adt/answer';
import { logVerbose } from '../cli/logVerbose';
import { flattenTree } from '../tree/flattenTree';
import { getNodeObjectSpec } from '../tree/getNodeObjectSpec';
import { mapAdtTypeToSupported } from '../tree/mapAdtTypeToSupported';
import type { BackupTreeNode, ObjectSpec, SupportedType } from '../types';
import { formatObjectSpec } from '../utils/formatObjectSpec';
import { objectId } from '../utils/objectId';

/**
 * The type code where-used is asked with, per backed-up type.
 *
 * Only codes adt-clients can address: since 23.0.0 it builds the where-used
 * URI the way activation does and throws, before any request, for a code it
 * cannot place. `INTF/OI` and `TABL/DS` are the codes ADT uses (the old
 * `INTF/IF` and `STRU/DT` are refused); a behavior implementation is a class
 * pool and is asked about as `CLAS/OC`. A message class has no address there
 * and is not asked about.
 */
const WHERE_USED_TYPE_MAP: Partial<Record<SupportedType, string>> = {
  package: 'DEVC/K',
  domain: 'DOMA/DD',
  dataElement: 'DTEL/DE',
  structure: 'TABL/DS',
  appendStructure: 'TABL/DS',
  table: 'TABL/DT',
  ddl: 'DDLS/DF',
  scalarFunction: 'DSFD/SCF',
  scalarFunctionImplementation: 'DSFI/SFI',
  class: 'CLAS/OC',
  interface: 'INTF/OI',
  program: 'PROG/P',
  transformation: 'XSLT/VT',
  functionGroup: 'FUGR/F',
  functionModule: 'FUGR/FF',
  serviceDefinition: 'SRVD/SRV',
  serviceBinding: 'SRVB/SVB',
  metadataExtension: 'DDLX/EX',
  behaviorDefinition: 'BDEF/BDO',
  behaviorImplementation: 'CLAS/OC',
};

function mapWhereUsedSpec(entry: {
  name: string;
  type: string;
}): (ObjectSpec & { id: string }) | undefined {
  const supported = mapAdtTypeToSupported(entry.type);
  if (!supported) {
    return undefined;
  }
  const spec: ObjectSpec = { type: supported, name: entry.name };
  return { ...spec, id: objectId(spec) };
}

/**
 * Every object that uses this one, over all object types.
 *
 * The three steps adt-clients' old `getWhereUsedList` ran: read the scope,
 * select every type in it (no request), run the search with that scope. Where
 * a system has no scope sub-resource (404 — some S/4 releases), the search
 * runs unscoped, with SAP's default type selection; that fallback used to
 * happen inside the library and is this CLI's decision now.
 */
async function whereUsed(
  client: AdtClient,
  objectName: string,
  objectType: string,
): Promise<IWhereUsedListResult> {
  const utils = client.getUtils({
    ...utilDocuments,
    whereUsed: utilWhereUsedReferences,
  });
  const params = { object_name: objectName, object_type: objectType };

  let scopeXml: string | undefined;
  const scope = await utils.getWhereUsedScope(params, {
    analyse: analyseException,
  });
  if (scope.ok) {
    scopeXml = utils.modifyWhereUsedScope(textOf(scope.getResult().value), {
      enableAll: true,
    });
  } else if (isAbsence(scope.getError())) {
    logVerbose(
      3,
      `  No where-used scope for ${objectName}; searching with the default scope`,
    );
  } else {
    requireOk(scope, `where-used scope of ${objectType} ${objectName}`);
  }

  const answer = await utils.getWhereUsed(
    { ...params, scopeXml },
    { analyse: analyseException },
  );
  return requireOk(answer, `where-used of ${objectType} ${objectName}`);
}

export async function collectTreeDependencies(
  client: AdtClient,
  root: BackupTreeNode,
): Promise<void> {
  const nodes = flattenTree(root).filter(
    (node) => node.type && node.restoreStatus === 'ok',
  );
  const nodeById = new Map<string, BackupTreeNode>();

  for (const node of nodes) {
    const spec = getNodeObjectSpec(node);
    if (!spec) {
      continue;
    }
    nodeById.set(objectId(spec), node);
  }

  for (const node of nodes) {
    const spec = getNodeObjectSpec(node);
    if (!spec) {
      continue;
    }
    const whereUsedType = WHERE_USED_TYPE_MAP[spec.type];
    if (!whereUsedType) {
      continue;
    }
    const objectName =
      spec.type === 'functionModule' && spec.functionGroupName
        ? `${spec.functionGroupName}|${spec.name}`
        : spec.name;

    try {
      logVerbose(3, `  Fetching dependencies for ${objectName}...`);
      const result = await whereUsed(client, objectName, whereUsedType);

      logVerbose(
        3,
        `  Raw references found for ${objectName}: ${result.totalReferences}`,
      );

      const usedBy = new Set<string>();
      for (const ref of result.references) {
        const usedSpec = mapWhereUsedSpec(ref);
        if (!usedSpec) {
          logVerbose(
            4,
            `    Skip: unknown type/name for ${ref.type}:${ref.name}`,
          );
          continue;
        }
        if (usedSpec.id === objectId(spec)) {
          continue;
        }
        if (!nodeById.has(usedSpec.id)) {
          logVerbose(
            4,
            `    Skip: object not in backup tree ${usedSpec.id} (found matches: ${Array.from(
              nodeById.keys(),
            )
              .filter((k) => k.includes(usedSpec.name))
              .join(', ')})`,
          );
          continue;
        }
        usedBy.add(
          formatObjectSpec({
            type: usedSpec.type,
            name: usedSpec.name,
            functionGroupName: usedSpec.functionGroupName,
          }),
        );
      }

      if (usedBy.size > 0) {
        node.usedBy = Array.from(usedBy).sort();
        logVerbose(
          2,
          `  Dependencies collected for ${objectName}: ${node.usedBy.join(', ')}`,
        );
      } else {
        logVerbose(
          3,
          `  No internal dependencies found for ${objectName} (after filtering)`,
        );
      }
    } catch (error: unknown) {
      logVerbose(
        2,
        `Warning: failed to collect dependencies for ${node.adtType}:${
          node.name
        }: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
}
