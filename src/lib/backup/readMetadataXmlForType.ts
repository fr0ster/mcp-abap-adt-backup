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
    switch (type) {
      case 'package': {
        const state = await client.getPackage().readMetadata({ packageName: name });
        return responseToText(state.metadataResult);
      }
      case 'class': {
        const state = await client.getClass().readMetadata({ className: name });
        return responseToText(state.metadataResult);
      }
      case 'interface': {
        const state = await client.getInterface().readMetadata({ interfaceName: name });
        return responseToText(state.metadataResult);
      }
      case 'domain': {
        const state = await client.getDomain().readMetadata({ domainName: name });
        return responseToText(state.metadataResult);
      }
      case 'dataElement': {
        const state = await client.getDataElement().readMetadata({ dataElementName: name });
        return responseToText(state.metadataResult);
      }
      case 'table': {
        const state = await client.getTable().readMetadata({ tableName: name });
        return responseToText(state.metadataResult);
      }
      case 'tableType': {
        const state = await client.getTableType().readMetadata({ tableTypeName: name });
        return responseToText(state.metadataResult);
      }
      case 'structure': {
        const state = await client.getStructure().readMetadata({ structureName: name });
        return responseToText(state.metadataResult);
      }
      case 'view': {
        const state = await client.getView().readMetadata({ viewName: name });
        return responseToText(state.metadataResult);
      }
      case 'behaviorDefinition': {
        const state = await client.getBehaviorDefinition().read({ name }, 'active');
        return responseToText(state?.readResult);
      }
      case 'serviceDefinition': {
        const state = await client.getServiceDefinition().readMetadata({ serviceDefinitionName: name });
        return responseToText(state.metadataResult);
      }
      case 'serviceBinding': {
        const state = await client.getServiceBinding().readMetadata({ bindingName: name });
        return responseToText(state.metadataResult);
      }
      case 'metadataExtension': {
        const state = await client.getMetadataExtension().readMetadata({ name });
        return responseToText(state.metadataResult);
      }
      case 'behaviorImplementation': {
        const state = await client.getBehaviorImplementation().readMetadata({ className: name });
        return responseToText(state.metadataResult);
      }
      case 'enhancement': {
        const state = await client.getEnhancement().read({ enhancementName: name, enhancementType: 'enhoxh' }, 'active');
        return responseToText(state?.readResult);
      }
      default:
        return undefined;
    }
  } catch (error: any) {
    const status = error.status || error.response?.status;
    const message = error.message || String(error);
    
    // Some SAP systems return 404 as error message instead of status code
    const isNotFound = status === 404 || status === 410 || 
                      /not found/i.test(message) || 
                      /does not exist/i.test(message) ||
                      /ExceptionResourceNotFound/i.test(message);

    if (isNotFound) {
      return null;
    }
    throw error;
  }
}
