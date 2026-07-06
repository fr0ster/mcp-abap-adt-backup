import type { SupportedType } from '../types';

// Message classes (MSAG) are not activatable — they must never be sent to
// activateObjectsGroup. Everything else follows the normal activate-on-create
// / bulk-activate flow.
const NON_ACTIVATABLE: ReadonlySet<SupportedType> = new Set(['messageClass']);

export function isActivatable(type?: SupportedType): boolean {
  return type ? !NON_ACTIVATABLE.has(type) : true;
}
