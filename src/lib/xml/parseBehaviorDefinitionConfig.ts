import type { IBehaviorDefinitionConfig } from '@mcp-abap-adt/adt-clients';
import { xmlParser } from '../constants/xmlParser';
import type { NodeValue } from '../types';
import { findAttribute } from './findAttribute';
import { findNode } from './findNode';
import { findNodeValue } from './findNodeValue';
import { getNodeAttribute } from './getNodeAttribute';

export function parseBehaviorDefinitionConfig(
  xml: string,
): Partial<IBehaviorDefinitionConfig> {
  const parsed = xmlParser.parse(xml) as NodeValue;
  const root =
    findNode(parsed, [
      'bdef:behaviorDefinition',
      'behaviorDefinition',
      'bdef:bdef',
      'bdef',
    ]) ?? parsed;

  const name =
    getNodeAttribute(root, 'adtcore:name') ||
    findAttribute(root, 'adtcore:name');
  const description =
    getNodeAttribute(root, 'adtcore:description') ||
    findAttribute(root, 'adtcore:description');

  const packageRef = findNode(root, ['adtcore:packageRef', 'packageRef']);
  const packageName =
    getNodeAttribute(packageRef, 'adtcore:name') ||
    findAttribute(packageRef, 'adtcore:name');

  const implementationType = (findNodeValue(root, [
    'bdef:implementationType',
    'implementationType',
  ]) ||
    getNodeAttribute(root, 'bdef:implementationType') ||
    findAttribute(root, 'bdef:implementationType')) as
    | IBehaviorDefinitionConfig['implementationType']
    | undefined;

  const rootEntity =
    findNodeValue(root, ['bdef:rootEntity', 'rootEntity']) ||
    getNodeAttribute(root, 'bdef:rootEntity') ||
    findAttribute(root, 'bdef:rootEntity');

  return {
    name,
    description,
    packageName,
    implementationType: implementationType || undefined,
    rootEntity: rootEntity || undefined,
  };
}
