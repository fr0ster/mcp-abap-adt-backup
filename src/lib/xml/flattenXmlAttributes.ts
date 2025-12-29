import { xmlParser } from '../constants/xmlParser';
import type { NodeRecord, NodeValue } from '../types';

const ARRAY_KEY_ATTRS = ['rel', 'name', 'id', 'type', 'href', 'title'];

function getAttrValue(record: NodeRecord, attr: string): string | undefined {
  const value = record[`@_${attr}`];
  return typeof value === 'string' && value.trim() ? value : undefined;
}

function buildArrayItemKey(item: NodeRecord): string | undefined {
  const parts: string[] = [];
  for (const attr of ARRAY_KEY_ATTRS) {
    const value = getAttrValue(item, attr);
    if (value) {
      parts.push(`${attr}=${value}`);
    }
  }
  if (parts.length === 0) {
    return undefined;
  }
  return parts.join('|');
}

function normalizeKey(key: string): string {
  return key.replace(/[[\]\s]/g, '_');
}

function visit(value: NodeValue, path: string, out: Map<string, string>): void {
  if (Array.isArray(value)) {
    const entries = value.map((item) => {
      const record =
        item && typeof item === 'object' && !Array.isArray(item)
          ? (item as NodeRecord)
          : undefined;
      const key = record ? buildArrayItemKey(record) : undefined;
      return { item, key };
    });
    const counts = new Map<string, number>();
    entries.sort((a, b) => {
      if (!a.key && !b.key) {
        return 0;
      }
      if (!a.key) {
        return 1;
      }
      if (!b.key) {
        return -1;
      }
      return a.key.localeCompare(b.key);
    });
    entries.forEach(({ item, key }, index) => {
      if (!key) {
        visit(item as NodeValue, `${path}[${index}]`, out);
        return;
      }
      const normalized = normalizeKey(key);
      const nextCount = (counts.get(normalized) || 0) + 1;
      counts.set(normalized, nextCount);
      const suffix = nextCount > 1 ? `#${nextCount}` : '';
      visit(item as NodeValue, `${path}[${normalized}${suffix}]`, out);
    });
    return;
  }

  if (!value || typeof value !== 'object') {
    return;
  }

  const record = value as NodeRecord;
  for (const [key, child] of Object.entries(record)) {
    if (key.startsWith('@_')) {
      const attrName = key.slice(2);
      const attrValue =
        typeof child === 'string' ? child : JSON.stringify(child);
      const attrPath = path ? `${path}@${attrName}` : `@${attrName}`;
      out.set(attrPath, attrValue);
      continue;
    }
    const nextPath = path ? `${path}.${key}` : key;
    visit(child as NodeValue, nextPath, out);
  }
}

export function flattenXmlAttributes(xml: string): Map<string, string> {
  const parsed = xmlParser.parse(xml) as NodeValue;
  const out = new Map<string, string>();
  visit(parsed, '', out);
  return out;
}
