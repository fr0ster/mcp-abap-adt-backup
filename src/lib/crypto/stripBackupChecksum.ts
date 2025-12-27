import type { BackupFile, BackupTreeFile } from '../types';

export function stripBackupChecksum<T extends BackupFile | BackupTreeFile>(
  payload: T,
): T {
  const cloned = JSON.parse(JSON.stringify(payload)) as T;
  delete (cloned as { checksum?: string }).checksum;
  return cloned;
}
