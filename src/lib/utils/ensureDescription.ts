import type { BackupConfig } from '../types';

export function ensureDescription(
  config: BackupConfig,
  fallback: string,
): BackupConfig {
  if (!config.description) {
    return { ...config, description: fallback };
  }
  return config;
}
