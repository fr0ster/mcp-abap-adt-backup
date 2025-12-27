import type { IDomainConfig } from '@mcp-abap-adt/adt-clients';
import { xmlParser } from '../constants/xmlParser';
import type { NodeValue } from '../types';
import { findAttribute } from './findAttribute';
import { findNode } from './findNode';
import { findNodeValue } from './findNodeValue';
import { getNodeAttribute } from './getNodeAttribute';
import { toBoolean } from './toBoolean';
import { toNumber } from './toNumber';

export function parseDomainConfig(xml: string): Partial<IDomainConfig> {
  const parsed = xmlParser.parse(xml) as NodeValue;
  const root = findNode(parsed, ['doma:domain', 'domain']) ?? parsed;
  const domainName =
    getNodeAttribute(root, 'adtcore:name') ||
    findAttribute(root, 'adtcore:name');
  const description =
    getNodeAttribute(root, 'adtcore:description') ||
    findAttribute(root, 'adtcore:description');
  const packageRef = findNode(root, ['adtcore:packageRef', 'packageRef']);
  const packageName =
    getNodeAttribute(packageRef, 'adtcore:name') ||
    findAttribute(packageRef, 'adtcore:name');

  const datatype = findNodeValue(root, ['doma:datatype', 'datatype']);
  const length = toNumber(findNodeValue(root, ['doma:length', 'length']));
  const decimals = toNumber(findNodeValue(root, ['doma:decimals', 'decimals']));
  const conversion_exit = findNodeValue(root, [
    'doma:conversionExit',
    'conversionExit',
  ]);
  const sign_exists = toBoolean(
    findNodeValue(root, ['doma:signExists', 'signExists']),
  );
  const lowercase = toBoolean(
    findNodeValue(root, ['doma:lowercase', 'lowercase']),
  );
  const valueTableRef = findNode(root, ['doma:valueTableRef', 'valueTableRef']);
  const value_table =
    getNodeAttribute(valueTableRef, 'adtcore:name') ||
    findAttribute(valueTableRef, 'adtcore:name');

  const fixedValuesNode = findNode(root, ['doma:fixValues', 'fixValues']);
  const fixed_values: Array<{ low: string; text: string }> = [];
  if (fixedValuesNode) {
    const fixValueEntries = findNode(fixedValuesNode, [
      'doma:fixValue',
      'fixValue',
    ]);
    const entries: NodeValue[] = Array.isArray(fixValueEntries)
      ? (fixValueEntries as NodeValue[])
      : fixValueEntries
        ? [fixValueEntries as NodeValue]
        : [];
    for (const entry of entries) {
      const low = findNodeValue(entry, ['doma:low', 'low']);
      const text = findNodeValue(entry, ['doma:text', 'text']);
      if (low && text) {
        fixed_values.push({ low, text });
      }
    }
  }

  return {
    domainName,
    description,
    packageName,
    datatype,
    length,
    decimals,
    conversion_exit,
    sign_exists,
    lowercase,
    value_table,
    fixed_values: fixed_values.length > 0 ? fixed_values : undefined,
  };
}
