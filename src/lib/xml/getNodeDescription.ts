import type { NodeRecord } from '../types';
import { getAttribute } from './getAttribute';

export function getNodeDescription(node: NodeRecord): string | undefined {
  return getAttribute(node, [
    '@_adtcore:description',
    '@_description',
    'adtcore:description',
    'description',
  ]);
}
