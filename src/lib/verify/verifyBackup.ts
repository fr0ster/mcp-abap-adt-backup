import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import { logVerbose } from '../cli/logVerbose';
import type { BackupFile, BackupTreeFile, BackupTreeNode } from '../types';
import { collectBackupNodes } from './collectBackupNodes';
import { getExpectedPackage } from './getExpectedPackage';
import type { VerifyEntry, VerifyStatus, VerifySummary } from './types';
import { verifyObjectInSystem } from './verifyObjectInSystem';
import { mapAdtTypeToSupported } from '../tree/mapAdtTypeToSupported';

export interface VerifyOptions {
  strict?: boolean;
  mode?: 'pre-restore' | 'post-restore';
}

export async function verifyBackup(
  client: AdtClient,
  backup: BackupFile | BackupTreeFile,
  options?: VerifyOptions,
): Promise<{ entries: VerifyEntry[]; summary: VerifySummary }> {
  logVerbose(1, `Verifying objects in backup (${options?.mode || 'pre-restore'} mode)...`);
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

  logVerbose(2, `Starting verification of ${nodes.length} objects...`);

  let count = 0;
  for (const node of nodes) {
    if (!node.type) continue;
    count++;
    
    // For verbosity level 2 (-vv), show progress chunks
    if (count % 10 === 0 || count === nodes.length) {
      logVerbose(2, `  Verifying: ${count}/${nodes.length} objects...`);
    }

    try {
      const entry = await verifyObjectInSystem(
        client,
        { type: node.type, name: node.name, functionGroupName: node.functionGroupName },
        getExpectedPackage(node.config),
        node.source || node.codeBase64,
        undefined,
        node.codeFormat || (node.source ? 'source' : undefined),
        mode === 'post-restore' ? 'inactive' : 'active'
      );
      
      // For verbosity level 3 (-vvv), show each result immediately
      if (entry.status !== 'ok' && entry.status !== 'missing') {
        logVerbose(2, `  [${entry.status.toUpperCase()}] ${node.type}:${node.name}: ${entry.message || ''}`);
      }
      
      entries.push(entry);
    } catch (error: any) {
      logVerbose(1, `  [ERROR] Failed to verify ${node.type}:${node.name}: ${error.message}`);
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

function buildSummary(entries: VerifyEntry[], options?: VerifyOptions): VerifySummary {
  const strict = options?.strict ?? false;
  const mode = options?.mode ?? 'pre-restore';
  
  const conflictStatuses = ['type-mismatch', 'package-mismatch', 'error'];
  if (strict) {
    conflictStatuses.push('source-mismatch');
  }
  
  if (mode === 'post-restore') {
    conflictStatuses.push('missing');
  }

  const okCount = entries.filter((e) => e.status === 'ok').length;
  const missingCount = entries.filter((e) => e.status === 'missing').length;

  return {
    total: entries.length,
    ok: mode === 'pre-restore' ? okCount + missingCount : okCount,
    missing: missingCount,
    typeMismatch: entries.filter((e) => e.status === 'type-mismatch').length,
    packageMismatch: entries.filter((e) => e.status === 'package-mismatch').length,
    sourceMismatch: entries.filter((e) => e.status === 'source-mismatch').length,
    unsupported: entries.filter((e) => e.status === 'unsupported').length,
    error: entries.filter((e) => e.status === 'error').length,
    conflicts: entries.filter((e) => conflictStatuses.includes(e.status)).length,
  };
}
