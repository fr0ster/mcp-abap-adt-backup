import type { BackupFile, BackupTreeFile } from '../types';
import { computeBackupChecksum } from './computeBackupChecksum';

export function verifyBackupChecksum(
  payload: BackupFile | BackupTreeFile,
): void {
  if (!payload.checksum) {
    return;
  }
  const expected = computeBackupChecksum(payload);
  if (payload.checksum !== expected) {
    throw new Error('Backup checksum mismatch');
  }
}
