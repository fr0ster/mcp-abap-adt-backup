import { formatObjectSpec } from '../utils/formatObjectSpec';
import type { VerifyEntry, VerifySummary } from './types';

export function formatVerifyResultsText(
  entries: VerifyEntry[],
  summary: VerifySummary,
  mode: 'pre-restore' | 'post-restore' = 'pre-restore',
  verbosity = 1,
): string {
  const lines: string[] = [];
  
  // Header line with summary
  lines.push(
    `Total: ${summary.total}, ok: ${summary.ok}, missing: ${summary.missing}, ` +
      `type-mismatch: ${summary.typeMismatch}, package-mismatch: ${summary.packageMismatch}, ` +
      `source-mismatch: ${summary.sourceMismatch}, unsupported: ${summary.unsupported}, ` +
      `error: ${summary.error}`,
  );

  for (const entry of entries) {
    const spec = formatObjectSpec({
      type: entry.type,
      name: entry.name,
      functionGroupName: entry.functionGroupName,
    });

    // Determine correctness based on mode
    // pre-restore: missing is GOOD (OK), existing is BAD (FAIL)
    // post-restore: existing is GOOD (OK), missing is BAD (FAIL)
    const isActuallyOk = mode === 'pre-restore' ? entry.status === 'missing' : entry.status === 'ok';
    
    // verbosity 1: show only failures
    // verbosity 2+: show everything
    if (verbosity < 2 && isActuallyOk) {
      continue;
    }

    let statusLabel = isActuallyOk ? 'OK' : 'FAIL';
    let detail = '';

    if (mode === 'pre-restore') {
      if (entry.status === 'missing') {
        detail = 'NOT in system (ready for restore)';
      } else if (entry.status === 'ok') {
        detail = `ALREADY EXISTS in package ${entry.actualPackage || 'unknown'}`;
      } else {
        detail = `${entry.status.toUpperCase()}: ${entry.message || ''}`;
      }
    } else {
      // post-restore
      if (entry.status === 'ok') {
        detail = `successfully restored in ${entry.actualPackage || 'unknown'}`;
      } else if (entry.status === 'missing') {
        detail = 'NOT FOUND after restore (failed)';
      } else {
        detail = `${entry.status.toUpperCase()}: ${entry.message || ''}`;
      }
    }

    lines.push(`${statusLabel} ${spec} | ${detail}`);
  }

  return lines.join('\n');
}
