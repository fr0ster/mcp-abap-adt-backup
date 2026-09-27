import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import type { ObjectSpec } from '../types';
import { extractMetadata } from '../xml/extractMetadata';
import { readMetadataXmlForType } from './readMetadataXmlForType';

/** Description and package out of the object's metadata document. */
export async function readBasicMetadata(
  client: AdtClient,
  spec: ObjectSpec,
): Promise<{ description?: string; packageName?: string }> {
  const xml = await readMetadataXmlForType(
    client,
    spec.type,
    spec.name,
    spec.functionGroupName,
  );
  return xml ? extractMetadata(xml) : {};
}
