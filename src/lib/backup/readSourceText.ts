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
    case 'serviceBinding': {
      const state = await client
        .getServiceBinding()
        .read({ bindingName: spec.name }, 'active');
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
    case 'enhancement': {
      // For enhancement we need to know the type, but since we don't have it in spec easily
      // and it's mostly used for BAdI implementations in this context, we try to read it
      // via general enhancement client if available or skip.
      // Assuming 'enhoxh' (Enhancement Implementation) as default for now if not specified.
      const state = await client
        .getEnhancement()
        .read(
          { enhancementName: spec.name, enhancementType: 'enhoxh' },
          'active',
        );
      return responseToText(state?.readResult);
    }
    default:
      return undefined;
  }
}
