import { xmlParser } from '../constants/xmlParser';
import type { NodeValue } from '../types';
import { findAttribute } from './findAttribute';
import { findNode } from './findNode';
import { findNodeValue } from './findNodeValue';
import { getNodeAttribute } from './getNodeAttribute';
import { toNumber } from './toNumber';

/**
 * What the backup records about a data element, read from its document.
 *
 * The backup's own record rather than `IDataElementConfig`, which describes a
 * create and has no labels, decimals or search help. The restore writes the
 * backed-up document, not this record.
 */
export interface DataElementBackupConfig {
  dataElementName?: string;
  description?: string;
  packageName?: string;
  dataType?: string;
  length?: number;
  decimals?: number;
  shortLabel?: string;
  mediumLabel?: string;
  longLabel?: string;
  headingLabel?: string;
  typeKind?: string;
  typeName?: string;
  searchHelp?: string;
  searchHelpParameter?: string;
  setGetParameter?: string;
}

export function parseDataElementConfig(xml: string): DataElementBackupConfig {
  const parsed = xmlParser.parse(xml) as NodeValue;
  const root = findNode(parsed, ['blue:wbobj', 'wbobj']) ?? parsed;
  const dataElementName =
    getNodeAttribute(root, 'adtcore:name') ||
    findAttribute(root, 'adtcore:name');
  const description =
    getNodeAttribute(root, 'adtcore:description') ||
    findAttribute(root, 'adtcore:description');
  const packageRef = findNode(root, ['adtcore:packageRef', 'packageRef']);
  const packageName =
    getNodeAttribute(packageRef, 'adtcore:name') ||
    findAttribute(packageRef, 'adtcore:name');

  const typeKind = findNodeValue(root, ['dtel:typeKind', 'typeKind']);
  const typeName = findNodeValue(root, ['dtel:typeName', 'typeName']);
  const dataType = findNodeValue(root, ['dtel:dataType', 'dataType']);
  const length = toNumber(
    findNodeValue(root, ['dtel:dataTypeLength', 'dataTypeLength']),
  );
  const decimals = toNumber(
    findNodeValue(root, ['dtel:dataTypeDecimals', 'dataTypeDecimals']),
  );
  const shortLabel = findNodeValue(root, [
    'dtel:shortFieldLabel',
    'shortFieldLabel',
  ]);
  const mediumLabel = findNodeValue(root, [
    'dtel:mediumFieldLabel',
    'mediumFieldLabel',
  ]);
  const longLabel = findNodeValue(root, [
    'dtel:longFieldLabel',
    'longFieldLabel',
  ]);
  const headingLabel = findNodeValue(root, [
    'dtel:headingFieldLabel',
    'headingFieldLabel',
  ]);
  const searchHelp = findNodeValue(root, ['dtel:searchHelp', 'searchHelp']);
  const searchHelpParameter = findNodeValue(root, [
    'dtel:searchHelpParameter',
    'searchHelpParameter',
  ]);
  const setGetParameter = findNodeValue(root, [
    'dtel:setGetParameter',
    'setGetParameter',
  ]);

  return {
    dataElementName,
    description,
    packageName,
    dataType: dataType || undefined,
    length,
    decimals,
    shortLabel,
    mediumLabel,
    longLabel,
    headingLabel,
    typeKind,
    typeName: typeName || undefined,
    searchHelp,
    searchHelpParameter,
    setGetParameter,
  };
}
