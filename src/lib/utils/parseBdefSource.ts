/**
 * Extracts rootEntity and implementationType from BDEF source code.
 * Used both during backup (to enrich config) and restore (fallback for old backups).
 */
export function parseBdefSource(source: string): {
  rootEntity?: string;
  implementationType?: 'Managed' | 'Unmanaged' | 'Abstract' | 'Projection';
} {
  const entityMatch = source.match(/define\s+behavior\s+for\s+([A-Z0-9_/]+)/i);
  const typeMatch = source.match(/^(managed|unmanaged|abstract|projection)\b/i);

  return {
    rootEntity: entityMatch?.[1] || undefined,
    implementationType: typeMatch
      ? ((typeMatch[1].charAt(0).toUpperCase() +
          typeMatch[1].slice(1).toLowerCase()) as
          | 'Managed'
          | 'Unmanaged'
          | 'Abstract'
          | 'Projection')
      : undefined,
  };
}
