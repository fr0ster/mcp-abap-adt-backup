import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import { analyseException } from '@mcp-abap-adt/adt-strategies';
import type { IAdtResponse } from '@mcp-abap-adt/interfaces-adt';
import { readAnswer } from '../adt/answer';
import type { ObjectSpec } from '../types';

type Version = 'active' | 'inactive';

/**
 * The one source request for a type, or `undefined` when the type has no
 * source of its own (its payload is a document — see readMetadataXmlForType).
 */
function readSourceRequest(
  client: AdtClient,
  spec: ObjectSpec,
  version: Version,
): Promise<IAdtResponse<unknown>> | undefined {
  // `analyseException`: a read refused inside a 2xx as `exc:exception` is a
  // failure with SAP's text, not a document to back up.
  const o = { analyse: analyseException };
  const name = spec.name;
  switch (spec.type) {
    case 'class':
      return client.getClass().read({ className: name }, version, o);
    case 'interface':
      return client.getInterface().read({ interfaceName: name }, version, o);
    case 'program':
      return client.getProgram().read({ programName: name }, version, o);
    case 'transformation':
      return client
        .getTransformation()
        .read({ transformationName: name }, version, o);
    case 'ddl':
      return client.getDdl().read({ ddlName: name }, version, o);
    case 'table':
      return client.getTable().read({ tableName: name }, version, o);
    case 'structure':
      return client.getStructure().read({ structureName: name }, version, o);
    case 'behaviorDefinition':
      return client.getBehaviorDefinition().read({ name }, version, o);
    case 'behaviorImplementation':
      return client
        .getBehaviorImplementation()
        .read({ className: name }, version, o);
    case 'serviceDefinition':
      return client
        .getServiceDefinition()
        .read({ serviceDefinitionName: name }, version, o);
    case 'metadataExtension':
      return client.getMetadataExtension().read({ name }, version, o);
    case 'functionModule':
      if (!spec.functionGroupName) return undefined;
      return client.getFunctionModule().read(
        {
          functionGroupName: spec.functionGroupName,
          functionModuleName: name,
        },
        version,
        o,
      );
    case 'functionInclude':
      if (!spec.functionGroupName) return undefined;
      return client
        .getFunctionInclude()
        .read(
          { functionGroupName: spec.functionGroupName, includeName: name },
          version,
          o,
        );
    case 'enhancement':
      return client
        .getEnhancement()
        .read({ enhancementName: name, enhancementType: 'enhoxh' }, version, o);
    case 'accessControl':
      return client
        .getAccessControl()
        .read({ accessControlName: name }, version, o);
    case 'scalarFunction':
      return client
        .getScalarFunction()
        .read({ scalarFunctionName: name }, version, o);
    case 'scalarFunctionImplementation':
      return client
        .getScalarFunctionImplementation()
        .read({ implementationName: name }, version, o);
    case 'appendStructure':
      return client
        .getAppendStructure()
        .read({ appendStructureName: name }, version, o);
    default:
      return undefined;
  }
}

/**
 * The object's source text.
 *
 * - a string: the source;
 * - `null`: nothing to take — a 404, or `200` with an empty body, which ADT
 *   answers for a missing object and an empty one alike;
 * - `undefined`: the type has no source (or a function-group child without its
 *   group name).
 *
 * Any other failure throws with SAP's message.
 */
export async function readSourceText(
  client: AdtClient,
  spec: ObjectSpec,
  version: Version = 'active',
): Promise<string | null | undefined> {
  const request = readSourceRequest(client, spec, version);
  if (!request) return undefined;
  return readAnswer(await request, `read source of ${spec.type} ${spec.name}`);
}
