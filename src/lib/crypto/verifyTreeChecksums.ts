import type { BackupTreeNode } from '../types';
import { computeCodeChecksum } from './computeCodeChecksum';

export function verifyTreeChecksums(
  node: BackupTreeNode,
  path: string[] = [],
): void {
  const label = node.type ? `${node.type}:${node.name}` : node.name;
  const nextPath = [...path, label];

  if (node.codeChecksum) {
    if (!node.codeBase64) {
      throw new Error(
        `Missing codeBase64 for checksum at ${nextPath.join(' > ')}`,
      );
    }
    const expected = computeCodeChecksum(node.codeBase64);
    if (expected !== node.codeChecksum) {
      throw new Error(`Code checksum mismatch at ${nextPath.join(' > ')}`);
    }
  }

  if (node.children && node.children.length > 0) {
    for (const child of node.children) {
      verifyTreeChecksums(child, nextPath);
    }
  }
}
