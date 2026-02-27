import { formatObjectSpec } from '../utils/formatObjectSpec';
import type { VerifyEntry, VerifySummary } from './types';

export function formatVerifyResultsText(
  entries: VerifyEntry[],
  summary: VerifySummary,
  mode: 'pre-restore' | 'post-restore' = 'pre-restore',
  verbosity = 1,
  skipIds?: Set<string>,
): string {
  const lines: string[] = [];

  // 1. Process objects list
  for (const entry of entries) {
    const spec = formatObjectSpec({
      type: entry.type,
      name: entry.name,
      functionGroupName: entry.functionGroupName,
    });

    const isMissing = entry.status === 'missing';
    const objectId = `${entry.type}:${entry.name}`;
    const isSkipped = skipIds?.has(objectId) ?? false;
    const isActuallyOk =
      mode === 'pre-restore'
        ? !isSkipped && (isMissing || entry.status === 'ok')
        : entry.status === 'ok';

    // logic:
    // verbosity 0: show nothing
    // verbosity 1: show only failures + skipped
    // verbosity 2+: show everything
    if (verbosity === 1 && isActuallyOk) {
      continue;
    }

    if (verbosity >= 2 || !isActuallyOk) {
      let label = '';
      let detail = '';

      if (mode === 'pre-restore') {
        if (isMissing) {
          label = 'CREATE';
          detail = 'New object (not in system)';
        } else if (isSkipped) {
          label = 'SKIP  ';
          detail = `Existing object skipped (in package ${entry.actualPackage || 'unknown'})`;
        } else if (
          entry.status === 'ok' ||
          entry.status === 'package-mismatch' ||
          entry.status === 'source-mismatch'
        ) {
          label = 'UPDATE';
          detail = `Existing object in package ${entry.actualPackage || 'unknown'}`;
        } else {
          label = 'ERROR ';
          detail = entry.message || entry.status;
        }
      } else {
        // post-restore
        if (entry.status === 'ok') {
          label = 'OK     ';
          detail = `successfully restored in ${entry.actualPackage}`;
        } else if (isMissing) {
          label = 'FAILED ';
          detail = 'NOT FOUND after restore';
        } else {
          label = 'ERROR  ';
          detail = entry.message || entry.status;
        }
      }
      lines.push(`${label} ${spec} | ${detail}`);
    }
  }

  // 2. Summary - ALWAYS show at the bottom
  const summaryParts = [
    `Total: ${summary.total}`,
    `ok: ${summary.ok}`,
    `missing: ${summary.missing}`,
    `error: ${summary.error}`,
    `conflicts: ${summary.conflicts}`,
  ];

  if (mode === 'pre-restore') {
    if (summary.create !== undefined)
      summaryParts.push(`create: ${summary.create}`);
    if (summary.update !== undefined)
      summaryParts.push(`update: ${summary.update}`);
    if (summary.skip !== undefined && summary.skip > 0)
      summaryParts.push(`skip: ${summary.skip}`);
  }

  if (lines.length > 0) {
    lines.push(`\n${'='.repeat(40)}`);
  }
  lines.push(`Summary (${mode}): ${summaryParts.join(', ')}`);
  if (lines.length > 1) {
    lines.push('='.repeat(40));
  }

  return lines.join('\n');
}
