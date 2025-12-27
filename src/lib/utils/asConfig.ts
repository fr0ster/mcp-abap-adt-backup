import type { BackupConfig } from '../types';

export function asConfig<T>(config: BackupConfig): T {
  return config as T;
}
