import type { BackupTreeNode } from '../types';
import { computeCodeChecksum } from './computeCodeChecksum';

export function updateTreeChecksums(node: BackupTreeNode): void {
  if (node.codeBase64) {
    node.codeChecksum = computeCodeChecksum(node.codeBase64);
  } else if (node.codeChecksum) {
    delete node.codeChecksum;
  }
  if (node.children && node.children.length > 0) {
    for (const child of node.children) {
      updateTreeChecksums(child);
    }
  }
}
