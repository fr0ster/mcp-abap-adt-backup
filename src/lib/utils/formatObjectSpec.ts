import type { ObjectSpec } from '../types';

export function formatObjectSpec(spec: ObjectSpec): string {
  if (spec.type === 'functionModule' || spec.type === 'functionInclude') {
    return `${spec.type}:${spec.functionGroupName}|${spec.name}`;
  }
  return `${spec.type}:${spec.name}`;
}
