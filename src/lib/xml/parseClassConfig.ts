import type { IClassConfig } from '@mcp-abap-adt/adt-clients';
import { xmlParser } from '../constants/xmlParser';
import type { NodeValue } from '../types';
import { findAttribute } from './findAttribute';
import { findNode } from './findNode';
import { findNodeValue } from './findNodeValue';
import { getNodeAttribute } from './getNodeAttribute';
import { toBoolean } from './toBoolean';

export function parseClassConfig(xml: string): Partial<IClassConfig> {
  const parsed = xmlParser.parse(xml) as NodeValue;
  const root =
    findNode(parsed, [
      'class:abapClass',
      'abapClass',
      'class:class',
      'class',
    ]) ?? parsed;

  const className =
    getNodeAttribute(root, 'adtcore:name') ||
    findAttribute(root, 'adtcore:name');
  const description =
    getNodeAttribute(root, 'adtcore:description') ||
    findAttribute(root, 'adtcore:description');

  const packageRef = findNode(root, ['adtcore:packageRef', 'packageRef']);
  const packageName =
    getNodeAttribute(packageRef, 'adtcore:name') ||
    findAttribute(packageRef, 'adtcore:name');

  const superclassRef = findNode(root, [
    'class:superClassRef',
    'superClassRef',
    'class:superclass',
    'superclass',
  ]);
  const superclass =
    getNodeAttribute(superclassRef, 'adtcore:name') ||
    findAttribute(superclassRef, 'adtcore:name') ||
    findNodeValue(root, ['class:superClassName', 'superClassName']);

  const final = toBoolean(
    getNodeAttribute(root, 'class:final') ||
      findAttribute(root, 'class:final') ||
      findNodeValue(root, ['class:final', 'final']),
  );

  const abstract = toBoolean(
    getNodeAttribute(root, 'class:abstract') ||
      findAttribute(root, 'class:abstract') ||
      findNodeValue(root, ['class:abstract', 'abstract']),
  );

  const visibility =
    getNodeAttribute(root, 'class:visibility') ||
    findAttribute(root, 'class:visibility') ||
    findNodeValue(root, ['class:visibility', 'visibility']);
  const createProtected = visibility === 'protected' ? true : undefined;

  const responsible =
    getNodeAttribute(root, 'adtcore:responsible') ||
    findAttribute(root, 'adtcore:responsible');

  const masterSystem =
    getNodeAttribute(root, 'adtcore:masterSystem') ||
    findAttribute(root, 'adtcore:masterSystem');

  return {
    className,
    description,
    packageName,
    superclass: superclass || undefined,
    final: final || undefined,
    abstract: abstract || undefined,
    createProtected: createProtected || undefined,
    responsible: responsible || undefined,
    masterSystem: masterSystem || undefined,
  };
}
