import type { ITableTypeConfig } from '@mcp-abap-adt/adt-clients';
import { xmlParser } from '../constants/xmlParser';
import type { NodeValue } from '../types';
import { findAttribute } from './findAttribute';
import { findNode } from './findNode';
import { findNodeValue } from './findNodeValue';
import { getNodeAttribute } from './getNodeAttribute';

export function parseTableTypeConfig(xml: string): Partial<ITableTypeConfig> {
  const parsed = xmlParser.parse(xml) as NodeValue;
  const root =
    findNode(parsed, ['ttyp:tableType', 'tableType', 'blue:wbobj', 'wbobj']) ??
    parsed;

  const tableTypeName =
    getNodeAttribute(root, 'adtcore:name') ||
    findAttribute(root, 'adtcore:name');
  const description =
    getNodeAttribute(root, 'adtcore:description') ||
    findAttribute(root, 'adtcore:description');

  const packageRef = findNode(root, ['adtcore:packageRef', 'packageRef']);
  const packageName =
    getNodeAttribute(packageRef, 'adtcore:name') ||
    findAttribute(packageRef, 'adtcore:name');

  const rowTypeRef = findNode(root, [
    'ttyp:rowTypeRef',
    'rowTypeRef',
    'ttyp:rowType',
    'rowType',
  ]);
  const rowTypeName =
    getNodeAttribute(rowTypeRef, 'adtcore:name') ||
    findAttribute(rowTypeRef, 'adtcore:name') ||
    findNodeValue(root, ['ttyp:rowTypeName', 'rowTypeName']);

  const rowTypeKind = (findNodeValue(root, [
    'ttyp:rowTypeKind',
    'rowTypeKind',
  ]) ||
    getNodeAttribute(root, 'ttyp:rowTypeKind') ||
    findAttribute(root, 'ttyp:rowTypeKind')) as
    | ITableTypeConfig['rowTypeKind']
    | undefined;

  const accessType = (findNodeValue(root, ['ttyp:accessType', 'accessType']) ||
    getNodeAttribute(root, 'ttyp:accessType') ||
    findAttribute(root, 'ttyp:accessType')) as
    | ITableTypeConfig['accessType']
    | undefined;

  const primaryKeyDefinition = (findNodeValue(root, [
    'ttyp:primaryKeyDefinition',
    'primaryKeyDefinition',
    'ttyp:keyDefinition',
    'keyDefinition',
  ]) ||
    getNodeAttribute(root, 'ttyp:primaryKeyDefinition') ||
    findAttribute(root, 'ttyp:primaryKeyDefinition')) as
    | ITableTypeConfig['primaryKeyDefinition']
    | undefined;

  const primaryKeyKind = (findNodeValue(root, [
    'ttyp:primaryKeyKind',
    'primaryKeyKind',
    'ttyp:keyKind',
    'keyKind',
  ]) ||
    getNodeAttribute(root, 'ttyp:primaryKeyKind') ||
    findAttribute(root, 'ttyp:primaryKeyKind')) as
    | ITableTypeConfig['primaryKeyKind']
    | undefined;

  return {
    tableTypeName,
    description,
    packageName,
    rowTypeName: rowTypeName || undefined,
    rowTypeKind: rowTypeKind || undefined,
    accessType: accessType || undefined,
    primaryKeyDefinition: primaryKeyDefinition || undefined,
    primaryKeyKind: primaryKeyKind || undefined,
  };
}
