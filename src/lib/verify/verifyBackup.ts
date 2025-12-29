import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import type { BackupFile, BackupTreeFile, BackupTreeNode } from '../types';
import { collectBackupNodes } from './collectBackupNodes';
import { getExpectedPackage } from './getExpectedPackage';
import type { VerifyEntry, VerifySummary } from './types';
import { verifyObjectInSystem } from './verifyObjectInSystem';

export async function verifyBackup(
  client: AdtClient,
  backup: BackupFile | BackupTreeFile,
  options?: { strict?: boolean },
): Promise<{ entries: VerifyEntry[]; summary: VerifySummary }> {
  const entries: VerifyEntry[] = [];

  if ((backup as BackupTreeFile).schemaVersion === 2) {
    const tree = backup as BackupTreeFile;
    const nodes: BackupTreeNode[] = [];
    collectBackupNodes(tree.root, nodes);
    for (const node of nodes) {
      if (!node.type) {
        continue;
      }
      const entry = await verifyObjectInSystem(
        client,
        {
          type: node.type,
          name: node.name,
          functionGroupName: node.functionGroupName,
        },
        getExpectedPackage(node.config),
        undefined,
        node.codeBase64,
        node.codeFormat,
      );
      entries.push(entry);
    }
  } else {
    const flat = backup as BackupFile;
    for (const obj of flat.objects) {
      const entry = await verifyObjectInSystem(
        client,
        {
          type: obj.type,
          name: obj.name,
          functionGroupName: obj.functionGroupName,
        },
        getExpectedPackage(obj.config),
        obj.source,
        undefined,
        obj.source ? 'source' : undefined,
      );
      entries.push(entry);
    }
  }

  const strict = options?.strict ?? false;
  const conflictStatuses = strict
    ? ['type-mismatch', 'package-mismatch', 'error', 'source-mismatch']
    : ['type-mismatch', 'package-mismatch', 'error'];

  const summary: VerifySummary = {
    total: entries.length,
    ok: entries.filter((entry) => entry.status === 'ok').length,
    missing: entries.filter((entry) => entry.status === 'missing').length,
    typeMismatch: entries.filter((entry) => entry.status === 'type-mismatch')
      .length,
    packageMismatch: entries.filter(
      (entry) => entry.status === 'package-mismatch',
    ).length,
    sourceMismatch: entries.filter(
      (entry) => entry.status === 'source-mismatch',
    ).length,
    unsupported: entries.filter((entry) => entry.status === 'unsupported')
      .length,
    error: entries.filter((entry) => entry.status === 'error').length,
    conflicts: entries.filter((entry) =>
      conflictStatuses.includes(entry.status),
    ).length,
  };

  return { entries, summary };
}
