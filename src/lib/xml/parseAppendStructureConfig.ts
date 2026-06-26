import { xmlParser } from '../constants/xmlParser';
import type { NodeValue } from '../types';
import { extractMetadata } from './extractMetadata';
import { findAttribute } from './findAttribute';

export function parseAppendStructureConfig(xml: string): {
  baseObject?: string;
  description?: string;
  packageName?: string;
} {
  const parsed = xmlParser.parse(xml) as NodeValue;
  const { description, packageName } = extractMetadata(xml);
  const baseObject =
    findAttribute(parsed, 'tabl:appendedTo') ||
    findAttribute(parsed, 'appendedTo') ||
    findAttribute(parsed, 'tabl:baseObject');
  return { baseObject, description, packageName };
}
// NOTE for the implementer: attribute names unverified at plan time; correct after
// the live smoke test (Task 6) if `baseObject` comes back empty. The three candidates
// probe the most likely ADT XML attribute names for the append target object.
