import type { NodeRecord } from '../types';
import { getAttribute } from './getAttribute';

export function getNodeName(node: NodeRecord): string | undefined {
  return getAttribute(node, [
    '@_adtcore:name',
    '@_name',
    'adtcore:name',
    'name',
  ]);
}
