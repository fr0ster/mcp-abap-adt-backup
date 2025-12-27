import type { ObjectSpec } from '../types';

export function objectId(spec: ObjectSpec): string {
  if (spec.type === 'functionModule') {
    return `${spec.type}:${spec.functionGroupName}|${spec.name}`;
  }
  return `${spec.type}:${spec.name}`;
}
