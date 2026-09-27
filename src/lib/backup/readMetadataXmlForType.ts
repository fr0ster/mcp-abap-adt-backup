import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import { analyseException } from '@mcp-abap-adt/adt-strategies';
import type { IAdtResponse } from '@mcp-abap-adt/interfaces-adt';
import { readAnswer } from '../adt/answer';
import type { SupportedType } from '../types';

/** The one metadata request for a type, or `undefined` when it has none here. */
function readMetadataRequest(
  client: AdtClient,
  type: SupportedType,
  name: string,
  functionGroupName?: string,
): Promise<IAdtResponse<unknown>> | undefined {
  const o = { analyse: analyseException };
  switch (type) {
    case 'package':
      return client.getPackage().readMetadata({ packageName: name }, o);
    case 'class':
      return client.getClass().readMetadata({ className: name }, o);
    case 'interface':
      return client.getInterface().readMetadata({ interfaceName: name }, o);
    case 'program':
      return client.getProgram().readMetadata({ programName: name }, o);
    case 'transformation':
      return client
        .getTransformation()
        .readMetadata({ transformationName: name }, o);
    case 'domain':
      return client.getDomain().readMetadata({ domainName: name }, o);
    case 'dataElement':
      return client.getDataElement().readMetadata({ dataElementName: name }, o);
    case 'table':
      return client.getTable().readMetadata({ tableName: name }, o);
    case 'tableType':
      return client.getTableType().readMetadata({ tableTypeName: name }, o);
    case 'structure':
      return client.getStructure().readMetadata({ structureName: name }, o);
    case 'ddl':
      return client.getDdl().readMetadata({ ddlName: name }, o);
    case 'behaviorDefinition':
      return client.getBehaviorDefinition().readMetadata({ name }, o);
    case 'behaviorImplementation':
      return client
        .getBehaviorImplementation()
        .readMetadata({ className: name }, o);
    case 'serviceDefinition':
      return client
        .getServiceDefinition()
        .readMetadata({ serviceDefinitionName: name }, o);
    case 'serviceBinding':
      return client.getServiceBinding().readMetadata({ bindingName: name }, o);
    case 'metadataExtension':
      return client.getMetadataExtension().readMetadata({ name }, o);
    case 'functionGroup':
      return client
        .getFunctionGroup()
        .readMetadata({ functionGroupName: name }, o);
    case 'functionModule':
      if (!functionGroupName) return undefined;
      return client
        .getFunctionModule()
        .readMetadata({ functionGroupName, functionModuleName: name }, o);
    case 'functionInclude':
      if (!functionGroupName) return undefined;
      return client
        .getFunctionInclude()
        .readMetadata({ functionGroupName, includeName: name }, o);
    case 'enhancement':
      return client
        .getEnhancement()
        .readMetadata({ enhancementName: name, enhancementType: 'enhoxh' }, o);
    case 'accessControl':
      return client
        .getAccessControl()
        .readMetadata({ accessControlName: name }, o);
    case 'scalarFunction':
      return client
        .getScalarFunction()
        .readMetadata({ scalarFunctionName: name }, o);
    case 'scalarFunctionImplementation':
      return client
        .getScalarFunctionImplementation()
        .readMetadata({ implementationName: name }, o);
    case 'appendStructure':
      return client
        .getAppendStructure()
        .readMetadata({ appendStructureName: name }, o);
    case 'messageClass':
      return client.getMessageClass().readMetadata({ name }, o);
    default:
      return undefined;
  }
}

/**
 * The object's metadata document.
 *
 * - a string: the document as ADT sent it;
 * - `null`: the object is not there — a 404/410, or a `200` with an empty
 *   body, which a not-yet-ready document read answers too;
 * - `undefined`: the type has no metadata read here.
 *
 * Any other failure throws with SAP's message: a refused read is not absence.
 */
export async function readMetadataXmlForType(
  client: AdtClient,
  type: SupportedType,
  name: string,
  functionGroupName?: string,
): Promise<string | null | undefined> {
  const request = readMetadataRequest(client, type, name, functionGroupName);
  if (!request) return undefined;
  return readAnswer(await request, `read metadata of ${type} ${name}`);
}
