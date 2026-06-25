import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import type { ObjectSpec } from '../types';
import { responseToText } from '../utils/responseToText';

export async function readSourceText(
  client: AdtClient,
  spec: ObjectSpec,
  version: 'active' | 'inactive' = 'active',
): Promise<string | null | undefined> {
  try {
    switch (spec.type) {
      case 'class': {
        const state = await client
          .getClass()
          .read({ className: spec.name }, version);
        return responseToText(state?.readResult);
      }
      case 'interface': {
        const state = await client
          .getInterface()
          .read({ interfaceName: spec.name }, version);
        return responseToText(state?.readResult);
      }
      case 'program': {
        const state = await client
          .getProgram()
          .read({ programName: spec.name }, version);
        return responseToText(state?.readResult);
      }
      case 'transformation': {
        const state = await client
          .getTransformation()
          .read({ transformationName: spec.name }, version);
        return responseToText(state?.readResult);
      }
      case 'ddl': {
        const state = await client
          .getDdl()
          .read({ ddlName: spec.name }, version);
        return responseToText(state?.readResult);
      }
      case 'table': {
        const state = await client
          .getTable()
          .read({ tableName: spec.name }, version);
        return responseToText(state?.readResult);
      }
      case 'structure': {
        const state = await client
          .getStructure()
          .read({ structureName: spec.name }, version);
        return responseToText(state?.readResult);
      }
      case 'tableType': {
        const state = await client
          .getTableType()
          .read({ tableTypeName: spec.name }, version);
        return responseToText(state?.readResult);
      }
      case 'behaviorDefinition': {
        const state = await client
          .getBehaviorDefinition()
          .read({ name: spec.name }, version);
        return responseToText(state?.readResult);
      }
      case 'behaviorImplementation': {
        const state = await client
          .getBehaviorImplementation()
          .read({ className: spec.name }, version);
        return responseToText(state?.readResult);
      }
      case 'serviceDefinition': {
        const state = await client
          .getServiceDefinition()
          .read({ serviceDefinitionName: spec.name }, version);
        return responseToText(state?.readResult);
      }
      case 'metadataExtension': {
        const state = await client
          .getMetadataExtension()
          .read({ name: spec.name }, version);
        return responseToText(state?.readResult);
      }
      case 'functionModule': {
        if (!spec.functionGroupName) return undefined;
        const state = await client.getFunctionModule().read(
          {
            functionGroupName: spec.functionGroupName,
            functionModuleName: spec.name,
          },
          version,
        );
        return responseToText(state?.readResult);
      }
      case 'functionInclude': {
        if (!spec.functionGroupName) return undefined;
        // read() returns the include source (adt-clients >= 5.8.0), consistent
        // with class/program/functionModule.
        const state = await client.getFunctionInclude().read(
          {
            functionGroupName: spec.functionGroupName,
            includeName: spec.name,
          },
          version,
        );
        return responseToText(state?.readResult);
      }
      case 'enhancement': {
        const state = await client
          .getEnhancement()
          .read(
            { enhancementName: spec.name, enhancementType: 'enhoxh' },
            version,
          );
        return responseToText(state?.readResult);
      }
      case 'accessControl': {
        const state = await client
          .getAccessControl()
          .read({ accessControlName: spec.name }, version);
        return responseToText(state?.readResult);
      }
      case 'scalarFunction': {
        const state = await client
          .getScalarFunction()
          .read({ scalarFunctionName: spec.name }, version);
        return responseToText(state?.readResult);
      }
      default:
        return undefined;
    }
  } catch (error: any) {
    if (error.status === 404 || error.response?.status === 404) {
      return null;
    }
    throw error;
  }
}
