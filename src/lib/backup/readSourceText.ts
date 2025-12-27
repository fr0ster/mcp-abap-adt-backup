import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import type { ObjectSpec } from '../types';
import { responseToText } from '../utils/responseToText';

export async function readSourceText(
  client: AdtClient,
  spec: ObjectSpec,
): Promise<string | undefined> {
  switch (spec.type) {
    case 'class': {
      const state = await client
        .getClass()
        .read({ className: spec.name }, 'active');
      return responseToText(state?.readResult);
    }
    case 'interface': {
      const state = await client
        .getInterface()
        .read({ interfaceName: spec.name }, 'active');
      return responseToText(state?.readResult);
    }
    case 'program': {
      const state = await client
        .getProgram()
        .read({ programName: spec.name }, 'active');
      return responseToText(state?.readResult);
    }
    case 'structure': {
      const state = await client
        .getStructure()
        .read({ structureName: spec.name }, 'active');
      return responseToText(state?.readResult);
    }
    case 'table': {
      const state = await client
        .getTable()
        .read({ tableName: spec.name }, 'active');
      return responseToText(state?.readResult);
    }
    case 'view': {
      const state = await client
        .getView()
        .read({ viewName: spec.name }, 'active');
      return responseToText(state?.readResult);
    }
    case 'tableType': {
      const state = await client
        .getTableType()
        .read({ tableTypeName: spec.name }, 'active');
      return responseToText(state?.readResult);
    }
    case 'functionModule': {
      if (!spec.functionGroupName) {
        return undefined;
      }
      const state = await client.getFunctionModule().read(
        {
          functionGroupName: spec.functionGroupName,
          functionModuleName: spec.name,
        },
        'active',
      );
      return responseToText(state?.readResult);
    }
    case 'serviceDefinition': {
      const state = await client
        .getServiceDefinition()
        .read({ serviceDefinitionName: spec.name }, 'active');
      return responseToText(state?.readResult);
    }
    case 'metadataExtension': {
      const state = await client
        .getMetadataExtension()
        .read({ name: spec.name }, 'active');
      return responseToText(state?.readResult);
    }
    case 'behaviorDefinition': {
      const state = await client
        .getBehaviorDefinition()
        .read({ name: spec.name }, 'active');
      return responseToText(state?.readResult);
    }
    case 'behaviorImplementation': {
      const state = await client
        .getBehaviorImplementation()
        .read({ className: spec.name }, 'active');
      return responseToText(state?.readResult);
    }
    default:
      return undefined;
  }
}
