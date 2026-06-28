export function parseAppendStructureSource(source: string): {
  baseObject?: string;
} {
  const m = source.match(/extend\s+type\s+([A-Za-z0-9_/]+)\s+with\b/i);
  return m ? { baseObject: m[1].toUpperCase() } : {};
}
