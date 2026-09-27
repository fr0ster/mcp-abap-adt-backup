/**
 * An ADT object document reduced to its definition, one element per line.
 *
 * What a save rewrites is dropped, so two documents compare equal exactly when
 * the object is defined the same: the change and creation stamps, the version
 * slot, the responsible person and master system (a restore writes its own),
 * every `etag`, and the `atom:link` navigation. Everything else — the type's
 * own attributes, value tables, row types, keys, labels — stays.
 */
export function canonicalDocument(xml: string): string {
  return xml
    .replace(/<\?xml[^>]*\?>/g, '')
    .replace(/<atom:link\b[^>]*\/>/g, '')
    .replace(
      /\s+adtcore:(changedAt|changedBy|createdAt|createdBy|version|responsible|masterSystem)="[^"]*"/g,
      '',
    )
    .replace(/\s+etag="[^"]*"/g, '')
    .replace(/>\s*</g, '>\n<')
    .trim();
}
