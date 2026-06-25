import { xmlParser } from '../constants/xmlParser';
import type { NodeValue } from '../types';
import { extractMetadata } from './extractMetadata';
import { findAttribute } from './findAttribute';

export function parseScalarFunctionImplementationConfig(xml: string): {
  scalarFunctionName?: string;
  engineValue?: 'sqlEngine' | 'amdpEngine';
  description?: string;
  packageName?: string;
} {
  const parsed = xmlParser.parse(xml) as NodeValue;
  const { description, packageName } = extractMetadata(xml);
  // ADT exposes the owning definition and the engine as attributes; names vary
  // by release, so probe the known candidates.
  const scalarFunctionName =
    findAttribute(parsed, 'dsfi:scalarFunction') ||
    findAttribute(parsed, 'scalarFunction') ||
    findAttribute(parsed, 'dsfi:functionName');
  const rawEngine =
    findAttribute(parsed, 'dsfi:engine') || findAttribute(parsed, 'engine');
  const engineValue =
    rawEngine === 'amdpEngine' || rawEngine === 'AMDP'
      ? 'amdpEngine'
      : 'sqlEngine';
  return { scalarFunctionName, engineValue, description, packageName };
}
// NOTE for the implementer: the exact attribute names are unverified (no live system at plan time).
// After the live smoke test (Task 6), correct the probed attribute names if `scalarFunctionName`
// comes back empty. This is a documented open risk in the spec.
