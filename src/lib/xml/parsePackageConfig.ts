import type { IPackageConfig } from '@mcp-abap-adt/adt-clients';
import { xmlParser } from '../constants/xmlParser';
import type { NodeValue } from '../types';
import { findAttribute } from './findAttribute';
import { findNode } from './findNode';
import { findNodeValue } from './findNodeValue';
import { getNodeAttribute } from './getNodeAttribute';

export function parsePackageConfig(xml: string): Partial<IPackageConfig> {
  const parsed = xmlParser.parse(xml) as NodeValue;
  const root = findNode(parsed, ['pak:package', 'package']) ?? parsed;
  const packageName =
    getNodeAttribute(root, 'adtcore:name') ||
    findAttribute(root, 'adtcore:name');
  const description =
    getNodeAttribute(root, 'adtcore:description') ||
    findAttribute(root, 'adtcore:description');
  const superPackageNode = findNode(root, ['pak:superPackage', 'superPackage']);
  const softwareComponentNode = findNode(root, [
    'pak:softwareComponent',
    'softwareComponent',
  ]);
  const superPackage =
    getNodeAttribute(superPackageNode, 'adtcore:name') ||
    findAttribute(superPackageNode, 'adtcore:name');
  const softwareComponent =
    getNodeAttribute(softwareComponentNode, 'pak:name') ||
    getNodeAttribute(softwareComponentNode, 'name') ||
    findAttribute(softwareComponentNode, 'pak:name') ||
    findAttribute(softwareComponentNode, 'name');
  const packageType = findNodeValue(root, ['pak:packageType', 'packageType']);
  const transportLayer = findNodeValue(root, [
    'pak:transportLayer',
    'transportLayer',
  ]);
  const applicationComponent = findNodeValue(root, [
    'pak:applicationComponent',
    'applicationComponent',
  ]);
  const responsible =
    getNodeAttribute(root, 'adtcore:responsible') ||
    findAttribute(root, 'adtcore:responsible');

  return {
    packageName,
    description,
    superPackage,
    softwareComponent,
    packageType,
    transportLayer,
    applicationComponent,
    responsible,
  };
}
