import YAML from 'yaml';
import type { BackupFile, BackupTreeFile } from '../types';
import { hashText } from './hashText';
import { stripBackupChecksum } from './stripBackupChecksum';

export function computeBackupChecksum(
  payload: BackupFile | BackupTreeFile,
): string {
  const sanitized = stripBackupChecksum(payload);
  const yamlText = YAML.stringify(sanitized, { lineWidth: 0 });
  return hashText(yamlText);
}
