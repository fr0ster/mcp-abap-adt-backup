import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import { readMetadataXmlForType } from '../backup/readMetadataXmlForType';
import { parseMessageClassXml } from './parseMessageClassXml';
import type { ParsedMessageClass } from './types';

/**
 * The message class and its messages, or `null` when it is not there.
 *
 * One request: a message has no resource of its own, so the class document
 * is the whole of it.
 */
export async function readMessageClass(
  client: AdtClient,
  name: string,
): Promise<ParsedMessageClass | null> {
  const xml = await readMetadataXmlForType(client, 'messageClass', name);
  if (!xml) return null;
  const parsed = parseMessageClassXml(xml);
  return parsed.name ? parsed : null;
}
