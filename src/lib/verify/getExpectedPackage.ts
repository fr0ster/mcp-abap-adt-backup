import type { BackupConfig } from '../types';

export function getExpectedPackage(config?: BackupConfig): string | undefined {
  if (!config || typeof config !== 'object') {
    return undefined;
  }
  const record = config as Record<string, unknown>;
  const name = record.packageName;
  if (typeof name !== 'string' || name.trim().length === 0) {
    return undefined;
  }
  return name;
}
