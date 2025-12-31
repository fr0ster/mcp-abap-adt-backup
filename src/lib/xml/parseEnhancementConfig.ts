import type { IEnhancementConfig } from '@mcp-abap-adt/adt-clients';
import { xmlParser } from '../constants/xmlParser';
import type { NodeValue } from '../types';
import { findAttribute } from './findAttribute';
import { findNode } from './findNode';
import { findNodeValue } from './findNodeValue';
import { getNodeAttribute } from './getNodeAttribute';

export function parseEnhancementConfig(
  xml: string,
): Partial<IEnhancementConfig> {
  const parsed = xmlParser.parse(xml) as NodeValue;
  const root =
    findNode(parsed, [
      'enho:enhancement',
      'enhancement',
      'enho:enho',
      'enho',
      'enhs:enhancementSpot',
      'enhancementSpot',
    ]) ?? parsed;

  const enhancementName =
    getNodeAttribute(root, 'adtcore:name') ||
    findAttribute(root, 'adtcore:name');
  const description =
    getNodeAttribute(root, 'adtcore:description') ||
    findAttribute(root, 'adtcore:description');

  const packageRef = findNode(root, ['adtcore:packageRef', 'packageRef']);
  const packageName =
    getNodeAttribute(packageRef, 'adtcore:name') ||
    findAttribute(packageRef, 'adtcore:name');

  // Enhancement type is determined by ADT type attribute
  const adtType =
    getNodeAttribute(root, 'adtcore:type') ||
    findAttribute(root, 'adtcore:type');

  let enhancementType: IEnhancementConfig['enhancementType'] | undefined;
  if (adtType) {
    if (adtType.includes('ENHO') || adtType.includes('enhoxh')) {
      enhancementType = 'enhoxh';
    } else if (adtType.includes('ENHB') || adtType.includes('enhoxhb')) {
      enhancementType = 'enhoxhb';
    } else if (adtType.includes('ENHH') || adtType.includes('enhoxhh')) {
      enhancementType = 'enhoxhh';
    } else if (adtType.includes('ENHS') || adtType.includes('enhsxs')) {
      enhancementType = 'enhsxs';
    } else if (adtType.includes('ENHSB') || adtType.includes('enhsxsb')) {
      enhancementType = 'enhsxsb';
    }
  }

  const enhancementSpotRef = findNode(root, [
    'enho:enhancementSpotRef',
    'enhancementSpotRef',
    'enho:spot',
    'spot',
  ]);
  const enhancementSpot =
    getNodeAttribute(enhancementSpotRef, 'adtcore:name') ||
    findAttribute(enhancementSpotRef, 'adtcore:name') ||
    findNodeValue(root, ['enho:enhancementSpot', 'enhancementSpot']);

  const badiDefinitionRef = findNode(root, [
    'enho:badiDefinitionRef',
    'badiDefinitionRef',
    'enho:badiDefinition',
    'badiDefinition',
  ]);
  const badiDefinition =
    getNodeAttribute(badiDefinitionRef, 'adtcore:name') ||
    findAttribute(badiDefinitionRef, 'adtcore:name') ||
    findNodeValue(root, ['enho:badiDefinition', 'badiDefinition']);

  return {
    enhancementName,
    description,
    packageName,
    enhancementType,
    enhancementSpot: enhancementSpot || undefined,
    badiDefinition: badiDefinition || undefined,
  };
}
