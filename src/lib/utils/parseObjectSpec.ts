import type { ObjectSpec } from '../types';
import { normalizeType } from './normalizeType';

export function parseObjectSpec(spec: string): ObjectSpec {
  const parts = spec.split(':');
  if (parts.length < 2) {
    throw new Error(`Invalid object spec: ${spec}`);
  }
  const type = normalizeType(parts[0]);
  const namePart = parts.slice(1).join(':').trim();
  if (!namePart) {
    throw new Error(`Missing name in object spec: ${spec}`);
  }

  if (type === 'functionModule' || type === 'functionInclude') {
    const split = namePart.split(/[|/]/);
    if (split.length !== 2) {
      throw new Error(`${type} spec must be GROUP|NAME or GROUP/NAME: ${spec}`);
    }
    return {
      type,
      functionGroupName: split[0].trim(),
      name: split[1].trim(),
    };
  }

  return { type, name: namePart };
}
