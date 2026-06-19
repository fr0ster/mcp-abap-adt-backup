import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import type { SupportedType } from '../types';
import { responseToText } from '../utils/responseToText';

export async function readMetadataXmlForType(
  client: AdtClient,
  type: SupportedType,
  name: string,
  functionGroupName?: string,
): Promise<string | null | undefined> {
  try {
    let result: string | undefined;
    switch (type) {
      case 'package': {
        const state = await client
          .getPackage()
          .readMetadata({ packageName: name });
        result = responseToText(state.metadataResult);
        break;
      }
      case 'class': {
        const state = await client.getClass().readMetadata({ className: name });
        result = responseToText(state.metadataResult);
        break;
      }
      case 'interface': {
        const state = await client
          .getInterface()
          .readMetadata({ interfaceName: name });
        result = responseToText(state.metadataResult);
        break;
      }
      case 'domain': {
        const state = await client
          .getDomain()
          .readMetadata({ domainName: name });
        result = responseToText(state.metadataResult);
        break;
      }
      case 'dataElement': {
        const state = await client
          .getDataElement()
          .readMetadata({ dataElementName: name });
        result = responseToText(state.metadataResult);
        break;
      }
      case 'table': {
        const state = await client.getTable().readMetadata({ tableName: name });
        result = responseToText(state.metadataResult);
        break;
      }
      case 'tableType': {
        const state = await client
          .getTableType()
          .readMetadata({ tableTypeName: name });
        result = responseToText(state.metadataResult);
        break;
      }
      case 'structure': {
        const state = await client
          .getStructure()
          .readMetadata({ structureName: name });
        result = responseToText(state.metadataResult);
        break;
      }
      case 'view': {
        const state = await client.getView().readMetadata({ viewName: name });
        result = responseToText(state.metadataResult);
        break;
      }
      case 'behaviorDefinition': {
        const state = await client
          .getBehaviorDefinition()
          .readMetadata({ name });
        result = responseToText(state.metadataResult);
        break;
      }
      case 'behaviorImplementation': {
        const state = await client
          .getBehaviorImplementation()
          .readMetadata({ className: name });
        result = responseToText(state.metadataResult);
        break;
      }
      case 'serviceDefinition': {
        const state = await client
          .getServiceDefinition()
          .readMetadata({ serviceDefinitionName: name });
        result = responseToText(state.metadataResult);
        break;
      }
      case 'serviceBinding': {
        const state = await client
          .getServiceBinding()
          .readMetadata({ bindingName: name });
        result = responseToText(state.metadataResult);
        break;
      }
      case 'metadataExtension': {
        const state = await client
          .getMetadataExtension()
          .readMetadata({ name });
        result = responseToText(state.metadataResult);
        break;
      }
      case 'functionGroup': {
        const state = await client
          .getFunctionGroup()
          .readMetadata({ functionGroupName: name });
        result = responseToText(state.metadataResult);
        break;
      }
      case 'functionInclude': {
        if (!functionGroupName) {
          return undefined;
        }
        const state = await client
          .getFunctionInclude()
          .readMetadata({ functionGroupName, includeName: name });
        result = responseToText(state.metadataResult);
        break;
      }
      case 'enhancement': {
        const state = await client
          .getEnhancement()
          .readMetadata({ enhancementName: name, enhancementType: 'enhoxh' });
        result = responseToText(state.metadataResult);
        break;
      }
      case 'accessControl': {
        const state = await client
          .getAccessControl()
          .readMetadata({ accessControlName: name });
        result = responseToText(state.metadataResult);
        break;
      }
      default:
        return undefined;
    }
    // ADT clients return undefined on 404 — treat as not found
    return result ?? null;
  } catch (error: any) {
    const status = error.status || error.response?.status;
    const message = error.message || String(error);

    const isNotFound =
      status === 404 ||
      status === 410 ||
      /not found/i.test(message) ||
      /does not exist/i.test(message) ||
      /ExceptionResourceNotFound/i.test(message);

    if (isNotFound) {
      return null;
    }
    throw error;
  }
}
