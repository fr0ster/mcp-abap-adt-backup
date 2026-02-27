import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import { logVerbose } from '../cli/logVerbose';
import type { BackupFile, BackupTreeFile } from '../types';
import { collectBackupNodes } from './collectBackupNodes';
import { getExpectedPackage } from './getExpectedPackage';
import type { VerifyEntry, VerifySummary } from './types';
import { verifyObjectInSystem } from './verifyObjectInSystem';

export interface VerifyOptions {
  strict?: boolean;
  mode?: 'pre-restore' | 'post-restore';
}

export async function verifyBackup(
  client: AdtClient,
  backup: BackupFile | BackupTreeFile,
  options?: VerifyOptions,
): Promise<{ entries: VerifyEntry[]; summary: VerifySummary }> {
  const mode = options?.mode || 'pre-restore';
  logVerbose(1, `Verifying objects in backup (${mode} mode)...`);
  const entries = await verifyIndividual(client, backup, options);
  return { entries, summary: buildSummary(entries, options) };
}

async function verifyIndividual(
  client: AdtClient,
  backup: BackupFile | BackupTreeFile,
  options?: VerifyOptions,
): Promise<VerifyEntry[]> {
  const entries: VerifyEntry[] = [];
  const nodes: any[] = [];
  const mode = options?.mode || 'pre-restore';

  if ((backup as BackupTreeFile).schemaVersion === 2) {
    collectBackupNodes((backup as BackupTreeFile).root, nodes);
  } else {
    nodes.push(...(backup as BackupFile).objects);
  }

  logVerbose(1, `Processing ${nodes.length} objects...`);

  let count = 0;
  for (const node of nodes) {
    if (!node.type) continue;
    count++;

    // Always show progress at level 1 or higher (-v, -vv)
    if (count % 10 === 0 || count === nodes.length) {
      logVerbose(
        1,
        `  Progress: ${count}/${nodes.length} objects processed...`,
      );
    }

    try {
      const entry = await verifyObjectInSystem(
        client,
        {
          type: node.type,
          name: node.name,
          functionGroupName: node.functionGroupName,
        },
        getExpectedPackage(node.config),
        node.source || node.codeBase64,
        undefined,
        node.codeFormat || (node.source ? 'source' : undefined),
        mode === 'post-restore' ? 'inactive' : 'active',
      );

      // Detailed object log ONLY for level 2 or higher (-vv)
      const actionLabel =
        mode === 'pre-restore'
          ? entry.status === 'missing'
            ? 'CREATE'
            : 'UPDATE'
          : entry.status === 'ok'
            ? 'OK    '
            : 'FAILED';

      logVerbose(2, `  [${actionLabel}] ${node.type}:${node.name}`);

      entries.push(entry);
    } catch (error: any) {
      logVerbose(1, `  [ERROR ] ${node.type}:${node.name} | ${error.message}`);
      entries.push({
        type: node.type,
        name: node.name,
        status: 'error',
        message: error.message,
      });
    }
  }
  return entries;
}

function buildSummary(
  entries: VerifyEntry[],
  options?: VerifyOptions,
): VerifySummary {
  const strict = options?.strict ?? false;
  const mode = options?.mode ?? 'pre-restore';

  const conflictStatuses = ['type-mismatch', 'package-mismatch', 'error'];
  if (strict) conflictStatuses.push('source-mismatch');
  if (mode === 'post-restore') conflictStatuses.push('missing');

  const missingCount = entries.filter((e) => e.status === 'missing').length;
  const okCount = entries.filter((e) => e.status === 'ok').length;
  const pkgMismatchCount = entries.filter(
    (e) => e.status === 'package-mismatch',
  ).length;
  const sourceMismatchCount = entries.filter(
    (e) => e.status === 'source-mismatch',
  ).length;

  return {
    total: entries.length,
    ok: mode === 'pre-restore' ? okCount + missingCount : okCount,
    missing: missingCount,
    create: missingCount,
    update: okCount + pkgMismatchCount + sourceMismatchCount,
    typeMismatch: entries.filter((e) => e.status === 'type-mismatch').length,
    packageMismatch: pkgMismatchCount,
    sourceMismatch: sourceMismatchCount,
    unsupported: entries.filter((e) => e.status === 'unsupported').length,
    error: entries.filter((e) => e.status === 'error').length,
    conflicts: entries.filter((e) => conflictStatuses.includes(e.status))
      .length,
  };
}
