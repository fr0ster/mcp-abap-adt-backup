import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import { readMetadataXmlForType } from '../backup/readMetadataXmlForType';
import { readSourceText } from '../backup/readSourceText';
import type { BackupTreeNode, SupportedType } from '../types';

export async function readPayloadForType(
  client: AdtClient,
  type: SupportedType,
  name: string,
  functionGroupName?: string,
): Promise<{ payload?: string; format?: BackupTreeNode['codeFormat'] }> {
  switch (type) {
    case 'class':
    case 'interface':
    case 'program':
    case 'transformation':
    case 'ddl':
    case 'structure':
    case 'table':
    case 'functionModule':
    case 'functionInclude':
    case 'serviceDefinition':
    case 'metadataExtension':
    case 'behaviorDefinition':
    case 'behaviorImplementation':
    case 'enhancement':
    case 'accessControl':
    case 'scalarFunction':
    case 'scalarFunctionImplementation':
    case 'appendStructure':
    case 'tableType': {
      const payload = await readSourceText(client, {
        type,
        name,
        functionGroupName,
      });
      return { payload: payload ?? undefined, format: 'source' };
    }
    case 'messageClass': {
      const state = await client.getMessageClass().read({ name });
      if (!state?.messageClass) {
        return {};
      }
      return { payload: JSON.stringify(state.messageClass), format: 'json' };
    }
    case 'domain':
    case 'dataElement':
    case 'package':
    case 'functionGroup':
    case 'serviceBinding': {
      const xml = await readMetadataXmlForType(
        client,
        type,
        name,
        functionGroupName,
      );
      return { payload: xml ?? undefined, format: 'xml' };
    }
    default:
      return {};
  }
}
