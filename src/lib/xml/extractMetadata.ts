import { xmlParser } from '../constants/xmlParser';
import type { NodeValue } from '../types';
import { findAttribute } from './findAttribute';
import { findPackageName } from './findPackageName';

export function extractMetadata(xml: string): {
  description?: string;
  packageName?: string;
} {
  const parsed = xmlParser.parse(xml) as NodeValue;
  const description =
    findAttribute(parsed, 'adtcore:description') ||
    findAttribute(parsed, 'description');
  const packageName = findPackageName(parsed);
  return { description, packageName };
}
