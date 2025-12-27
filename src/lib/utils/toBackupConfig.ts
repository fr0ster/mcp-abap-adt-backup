import type { BackupConfig } from '../types';

export function toBackupConfig(value: unknown): BackupConfig {
  return value as BackupConfig;
}
