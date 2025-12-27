import type { NodeRecord } from '../types';
import { getAttribute } from './getAttribute';

export function getNodeType(node: NodeRecord): string | undefined {
  return getAttribute(node, [
    '@_adtcore:type',
    '@_type',
    'adtcore:type',
    'type',
  ]);
}
