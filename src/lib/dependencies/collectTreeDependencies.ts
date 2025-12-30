import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import { logVerbose } from '../cli/logVerbose';
import { flattenTree } from '../tree/flattenTree';
import { getNodeObjectSpec } from '../tree/getNodeObjectSpec';
import { mapAdtTypeToSupported } from '../tree/mapAdtTypeToSupported';
import type { BackupTreeNode, ObjectSpec, SupportedType } from '../types';
import { formatObjectSpec } from '../utils/formatObjectSpec';
import { normalizeType } from '../utils/normalizeType';
import { objectId } from '../utils/objectId';
import { responseToText } from '../utils/responseToText';
import { parseWhereUsedXml } from '../xml/parseWhereUsedXml';

type WhereUsedSpec = ObjectSpec & { id: string };

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

function parseFunctionModuleName(
  name: string,
  parentName?: string,
): { group: string; name: string } | undefined {
  if (name.includes('|')) {
    const [group, moduleName] = name.split('|');
    if (group && moduleName) {
      return { group, name: moduleName };
    }
  }
  if (name.includes('/')) {
    const [group, moduleName] = name.split('/');
    if (group && moduleName) {
      return { group, name: moduleName };
    }
  }
  if (parentName) {
    return { group: parentName, name };
  }
  return undefined;
}

function mapWhereUsedSpec(entry: {
  name?: string;
  type?: string;
  parentName?: string;
}): WhereUsedSpec | undefined {
  if (!entry.name || !entry.type) {
    return undefined;
  }
  const rawType = entry.type.trim();
  let supported: SupportedType | undefined;
  if (rawType.includes('/')) {
    supported = mapAdtTypeToSupported(rawType);
  } else {
    try {
      supported = normalizeType(rawType);
    } catch {
      supported = undefined;
    }
  }
  if (!supported) {
    return undefined;
  }
  if (supported === 'functionModule') {
    const parsed = parseFunctionModuleName(entry.name, entry.parentName);
    if (!parsed) {
      return undefined;
    }
    const spec: ObjectSpec = {
      type: supported,
      name: parsed.name,
      functionGroupName: parsed.group,
    };
    return { ...spec, id: objectId(spec) };
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
      const scopeResponse = await client.getUtils().getWhereUsedScope({
        object_name: objectName,
        object_type: whereUsedType,
      });
      const scopeXml = responseToText(scopeResponse);
      if (!scopeXml) {
        continue;
      }
      const enabledScope = client
        .getUtils()
        .modifyWhereUsedScope(scopeXml, { enableAll: true });

      const response = await client.getUtils().getWhereUsed({
        object_name: objectName,
        object_type: whereUsedType,
        scopeXml: enabledScope,
      });
      const xml = responseToText(response);
      if (!xml) {
        logVerbose(3, `  Where-used response empty for ${objectName}`);
        continue;
      }
      const parsed = parseWhereUsedXml(xml);
      const referencing = parsed.filter(
        (entry) => entry.context === 'referencing',
      );
      const entries = referencing.length > 0 ? referencing : parsed;

      logVerbose(
        3,
        `  Raw references found for ${objectName}: ${entries.length}`,
      );

      const usedBy = new Set<string>();
      for (const entry of entries) {
        const usedSpec = mapWhereUsedSpec(entry);
        if (!usedSpec) {
          logVerbose(
            4,
            `    Skip: unknown type/name for ${entry.type}:${entry.name}`,
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
