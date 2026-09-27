import { XMLParser } from 'fast-xml-parser';
import type { ParsedMessage, ParsedMessageClass } from './types';

/*
 * Ported from @mcp-abap-adt/adt-clients (src/core/messageClass/xml.ts,
 * `parseMessageClass`), which since 23.0.0 no longer parses the class for its
 * caller: `readMetadata()` answers the document as it arrived. This reads it
 * into the backup's own shape and keeps only the fields the backup records —
 * no raw attribute bag, no master system or responsible person.
 */

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  parseAttributeValue: false,
  parseTagValue: false,
});

type XmlRecord = Record<string, unknown>;

function attributes(node: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!node || typeof node !== 'object') return out;
  for (const [key, value] of Object.entries(node as XmlRecord)) {
    if (key.startsWith('@_')) out[key.slice(2)] = String(value);
  }
  return out;
}

function asRecord(value: unknown): XmlRecord {
  return value && typeof value === 'object' ? (value as XmlRecord) : {};
}

/**
 * `mc:messageClass`, read. A document that is not one reads as a class with
 * no name and no messages; the caller decides what that means.
 */
export function parseMessageClassXml(xml: string): ParsedMessageClass {
  const root = asRecord(parser.parse(xml));
  const mc = asRecord(root['mc:messageClass'] ?? root.messageClass);
  const attrs = attributes(mc);
  const pkgRef = mc['adtcore:packageRef'] ?? mc.packageRef;
  const rawMessages = mc['mc:messages'] ?? mc.messages;
  const list: unknown[] = Array.isArray(rawMessages)
    ? rawMessages
    : rawMessages
      ? [rawMessages]
      : [];

  const messages: ParsedMessage[] = list.map((m) => {
    const ma = attributes(m);
    const message: ParsedMessage = {
      msgno: ma['mc:msgno'] ?? '',
      msgtext: ma['mc:msgtext'] ?? '',
    };
    if (ma['mc:selfexplainatory']) {
      message.selfExplanatory = ma['mc:selfexplainatory'] === 'true';
    }
    if (ma['adtcore:description']) {
      message.description = ma['adtcore:description'];
    }
    return message;
  });

  const parsed: ParsedMessageClass = {
    name: attrs['adtcore:name'] ?? '',
    messages,
  };
  if (attrs['adtcore:description']) {
    parsed.description = attrs['adtcore:description'];
  }
  const packageName = attributes(pkgRef)['adtcore:name'];
  if (packageName) parsed.packageName = packageName;
  if (attrs['adtcore:language']) parsed.language = attrs['adtcore:language'];
  if (attrs['adtcore:masterLanguage']) {
    parsed.masterLanguage = attrs['adtcore:masterLanguage'];
  }
  return parsed;
}
