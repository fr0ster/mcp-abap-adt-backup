import type { BackupConfig } from '../types';

/**
 * A parsed config as the record the backup stores. A copy rather than a cast:
 * the spread is a plain object literal, which the record type accepts as is.
 */
export function toBackupConfig(value: object): BackupConfig {
  return { ...value };
}
