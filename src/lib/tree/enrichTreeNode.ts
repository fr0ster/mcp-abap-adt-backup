import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import { readMetadataXmlForType } from '../backup/readMetadataXmlForType';
import { logVerbose } from '../cli/logVerbose';
import { encodeBase64 } from '../crypto/encodeBase64';
import type { BackupTreeNode } from '../types';
import { ensureDescription } from '../utils/ensureDescription';
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
  const mappedType = mapAdtTypeToSupported(node.adtType);
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

  if (node.children && node.children.length > 0) {
    const children: BackupTreeNode[] = [];
    for (const child of node.children) {
      children.push(
        await enrichTreeNode(child, client, includeCode, functionGroupName),
      );
    }
    nextNode.children = children;
  }

  return nextNode;
}
