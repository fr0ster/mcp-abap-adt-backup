import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import type { SupportedType } from '../types';
import { responseToText } from '../utils/responseToText';

export async function readMetadataXmlForType(
  client: AdtClient,
  type: SupportedType,
  name: string,
  functionGroupName?: string,
): Promise<string | undefined> {
  switch (type) {
    case 'class': {
      const state = await client.getClass().readMetadata({ className: name });
      return responseToText(state.metadataResult);
    }
    case 'interface': {
      const state = await client
        .getInterface()
        .readMetadata({ interfaceName: name });
      return responseToText(state.metadataResult);
    }
    case 'program': {
      const state = await client
        .getProgram()
        .readMetadata({ programName: name });
      return responseToText(state.metadataResult);
    }
    case 'structure': {
      const state = await client
        .getStructure()
        .readMetadata({ structureName: name });
      return responseToText(state.metadataResult);
    }
    case 'table': {
      const state = await client.getTable().readMetadata({ tableName: name });
      return responseToText(state.metadataResult);
    }
    case 'tableType': {
      const state = await client
        .getTableType()
        .readMetadata({ tableTypeName: name });
      return responseToText(state.metadataResult);
    }
    case 'domain': {
      const state = await client.getDomain().readMetadata({ domainName: name });
      return responseToText(state.metadataResult);
    }
    case 'dataElement': {
      const state = await client
        .getDataElement()
        .readMetadata({ dataElementName: name });
      return responseToText(state.metadataResult);
    }
    case 'functionGroup': {
      const state = await client
        .getFunctionGroup()
        .readMetadata({ functionGroupName: name });
      return responseToText(state.metadataResult);
    }
    case 'functionModule': {
      if (!functionGroupName) {
        return undefined;
      }
      const state = await client.getFunctionModule().readMetadata({
        functionGroupName,
        functionModuleName: name,
      });
      return responseToText(state.metadataResult);
    }
    case 'package': {
      const state = await client
        .getPackage()
        .readMetadata({ packageName: name });
      return responseToText(state.metadataResult);
    }
    case 'serviceDefinition': {
      const state = await client
        .getServiceDefinition()
        .readMetadata({ serviceDefinitionName: name });
      return responseToText(state.metadataResult);
    }
    case 'metadataExtension': {
      const state = await client.getMetadataExtension().readMetadata({ name });
      return responseToText(state.metadataResult);
    }
    case 'behaviorDefinition': {
      const state = await client.getBehaviorDefinition().readMetadata({ name });
      return responseToText(state.metadataResult);
    }
    case 'behaviorImplementation': {
      const state = await client
        .getBehaviorImplementation()
        .readMetadata({ className: name });
      return responseToText(state.metadataResult);
    }
    default:
      return undefined;
  }
}
