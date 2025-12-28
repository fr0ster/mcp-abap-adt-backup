import { formatObjectSpec } from '../utils/formatObjectSpec';
import type { VerifyEntry, VerifySummary } from './types';

export function formatVerifyResultsText(
  entries: VerifyEntry[],
  summary: VerifySummary,
): string {
  const lines: string[] = [];
  lines.push(
    `Total: ${summary.total}, ok: ${summary.ok}, missing: ${summary.missing}, ` +
      `type-mismatch: ${summary.typeMismatch}, package-mismatch: ${summary.packageMismatch}, ` +
      `source-mismatch: ${summary.sourceMismatch}, unsupported: ${summary.unsupported}, ` +
      `error: ${summary.error}`,
  );

  for (const entry of entries) {
    if (entry.status === 'ok') {
      continue;
    }
    const spec = formatObjectSpec({
      type: entry.type,
      name: entry.name,
      functionGroupName: entry.functionGroupName,
    });
    const parts = [`${entry.status} ${spec}`];
    if (entry.expectedPackage || entry.actualPackage) {
      parts.push(
        `package=${entry.expectedPackage ?? '-'} -> ${entry.actualPackage ?? '-'}`,
      );
    }
    if (entry.message) {
      parts.push(entry.message);
    }
    lines.push(parts.join(' | '));
  }

  return lines.join('\n');
}
