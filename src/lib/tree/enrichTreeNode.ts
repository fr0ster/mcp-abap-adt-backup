import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import { readMetadataXmlForType } from '../backup/readMetadataXmlForType';
import { logVerbose } from '../cli/logVerbose';
import { encodeBase64 } from '../crypto/encodeBase64';
import type { BackupTreeNode } from '../types';
import { ensureDescription } from '../utils/ensureDescription';
import { parseBdefSource } from '../utils/parseBdefSource';
import { parseBehaviorDefinitionFromClass } from '../utils/parseBehaviorDefinitionFromClass';
import { extractMetadata } from '../xml/extractMetadata';
import { buildConfigForNode } from './buildConfigForNode';
import { isRestoreImplemented } from './isRestoreImplemented';
import { mapAdtTypeToSupported } from './mapAdtTypeToSupported';
import { readPayloadForType } from './readPayloadForType';

export async function enrichTreeNode(
  node: BackupTreeNode,
  client: AdtClient,
  includeCode: boolean,
  parentFunctionGroupName?: string,
): Promise<BackupTreeNode> {
  // NOTE for Task 6: confirm the exact field on PackageHierarchyNode that carries the
  // append-structure marker. The heuristic below checks a hypothetical `appendStructure`
  // boolean flag and an `objectType` text containing "append". If NEITHER is present in the
  // live hierarchy response, an append structure is silently backed up as a plain `structure`
  // (losing baseObject). Task-6 live test MUST confirm appends classify as appendStructure
  // (smoke checklist gating check). If the hierarchy lacks a flag, add a content-inspection
  // fallback here: fetch the metadata XML and detect the DDIC EXTEND/append marker in it,
  // then set isAppend accordingly before calling mapAdtTypeToSupported.
  const rawNode = node as BackupTreeNode & {
    appendStructure?: boolean;
    objectType?: string;
  };
  const isAppend =
    /append/i.test(rawNode.objectType ?? '') ||
    rawNode.appendStructure === true;
  const mappedType = mapAdtTypeToSupported(node.adtType, { isAppend });
  const functionGroupName =
    mappedType === 'functionGroup'
      ? node.name
      : mappedType === 'functionModule'
        ? parentFunctionGroupName
        : parentFunctionGroupName;
  const { restoreStatus: _restoreStatus, ...nodeBase } = node;
  const nextNode: BackupTreeNode = {
    ...nodeBase,
    type: mappedType,
    functionGroupName,
  };
  if (mappedType) {
    nextNode.restoreStatus = isRestoreImplemented(mappedType)
      ? 'ok'
      : 'not-implemented';
  }

  logVerbose(
    3,
    `Node: ${node.name} [${node.adtType || 'unknown'}] -> ${mappedType || 'unknown'} (${nextNode.restoreStatus})`,
  );

  if (!mappedType && node.adtType) {
    logVerbose(1, `  [SKIP] ${node.name} — unsupported type ${node.adtType}`);
  }

  if (mappedType && includeCode) {
    logVerbose(2, `  Reading ${mappedType}:${node.name}`);
  }

  const metadataXml =
    mappedType && includeCode
      ? await readMetadataXmlForType(client, mappedType, node.name)
      : undefined;

  if (!nextNode.description && metadataXml) {
    nextNode.description = extractMetadata(metadataXml).description;
  }

  if (mappedType && includeCode) {
    const config = await buildConfigForNode(
      mappedType,
      node.name,
      functionGroupName,
      metadataXml ?? undefined,
    );
    if (config) {
      nextNode.config = ensureDescription(config, node.name);
    }
  }

  if (mappedType && includeCode) {
    const payload = await readPayloadForType(
      client,
      mappedType,
      node.name,
      functionGroupName,
    );
    if (payload.payload) {
      nextNode.codeBase64 = encodeBase64(payload.payload);
      nextNode.codeFormat = payload.format;
      if (mappedType === 'behaviorDefinition') {
        const bdefInfo = parseBdefSource(payload.payload);
        if (bdefInfo.rootEntity || bdefInfo.implementationType) {
          nextNode.config = {
            ...(nextNode.config || {}),
            ...bdefInfo,
          };
        }
      }
      if (mappedType === 'behaviorImplementation') {
        const behaviorDefinition = parseBehaviorDefinitionFromClass(
          payload.payload,
        );
        if (behaviorDefinition) {
          nextNode.config = {
            ...(nextNode.config || {}),
            behaviorDefinition,
          };
        }
      }
    }
  }

  // A function group's function modules (FUGR/FF) and includes (FUGR/I) are not
  // returned by the package hierarchy — enumerate them and attach as children so
  // their source is captured. Skip the generated `L<FUGR>UXX` collector (no
  // developer content; regenerated on restore).
  const childNodes: BackupTreeNode[] = node.children ? [...node.children] : [];
  if (mappedType === 'functionGroup' && includeCode) {
    const utils = client.getUtils();
    const [fmNames, includeNames] = await Promise.all([
      utils.listFunctionModules(node.name),
      utils.listFunctionGroupIncludes(node.name),
    ]);
    const generatedCollector = `L${node.name.toUpperCase()}UXX`;
    const enumerated: BackupTreeNode[] = [
      ...fmNames.map((name) => ({ name, adtType: 'FUGR/FF' })),
      ...includeNames
        .filter((name) => name.toUpperCase() !== generatedCollector)
        .map((name) => ({ name, adtType: 'FUGR/I' })),
    ];
    const present = new Set(childNodes.map((c) => c.name.toUpperCase()));
    for (const child of enumerated) {
      if (!present.has(child.name.toUpperCase())) {
        childNodes.push(child);
      }
    }
    logVerbose(
      2,
      `  FUGR ${node.name}: +${fmNames.length} FM, +${enumerated.length - fmNames.length} include(s)`,
    );
  }

  if (childNodes.length > 0) {
    const children: BackupTreeNode[] = [];
    for (const child of childNodes) {
      children.push(
        await enrichTreeNode(child, client, includeCode, functionGroupName),
      );
    }
    nextNode.children = children;
  }

  return nextNode;
}
