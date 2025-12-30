import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import { logVerbose } from '../cli/logVerbose';
import { flattenTree } from '../tree/flattenTree';
import { getNodeObjectSpec } from '../tree/getNodeObjectSpec';
import { mapAdtTypeToSupported } from '../tree/mapAdtTypeToSupported';
import type { BackupTreeNode, ObjectSpec, SupportedType } from '../types';
import { formatObjectSpec } from '../utils/formatObjectSpec';
import { objectId } from '../utils/objectId';

const WHERE_USED_TYPE_MAP: Partial<Record<SupportedType, string>> = {
  package: 'DEVC/K',
  domain: 'DOMA/DD',
  dataElement: 'DTEL/DE',
  structure: 'STRU/DT',
  table: 'TABL/DT',
  view: 'DDLS/DF',
  class: 'CLAS/OC',
  interface: 'INTF/IF',
  program: 'PROG/P',
  functionGroup: 'FUGR/F',
  functionModule: 'FUGR/FF',
  serviceDefinition: 'SRVD/SRV',
  metadataExtension: 'DDLX/EX',
  behaviorDefinition: 'BDEF/BDO',
  behaviorImplementation: 'BIMP/BIM',
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
      const result = await client.getUtils().getWhereUsedList({
        object_name: objectName,
        object_type: whereUsedType,
        enableAllTypes: true,
      });

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
    } catch (error: any) {
      logVerbose(
        2,
        `  Error getting dependencies for ${objectName}: ${error.message}`,
      );
    }
  }
}
