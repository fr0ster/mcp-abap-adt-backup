import type { IObjectReference } from '@mcp-abap-adt/interfaces-adt';

/**
 * The reference adt-clients takes for an object in a group call — activation
 * or deletion. A function module or include is addressed under its function
 * group, so it carries the group as `parentName`; adt-clients refuses one
 * without it before any request is sent, which leaves the whole group undone.
 */
export function objectReference(object: {
  name: string;
  adtType: string;
  functionGroupName?: string;
}): IObjectReference {
  const reference: IObjectReference = {
    name: object.name,
    type: object.adtType,
  };
  if (
    object.functionGroupName &&
    object.adtType.startsWith('FUGR/') &&
    object.adtType !== 'FUGR/F'
  ) {
    reference.parentName = object.functionGroupName;
  }
  return reference;
}
