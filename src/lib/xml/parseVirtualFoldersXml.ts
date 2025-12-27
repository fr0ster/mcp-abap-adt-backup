import { xmlParser } from '../constants/xmlParser';
import type {
  NodeRecord,
  VirtualFolderEntry,
  VirtualObjectEntry,
} from '../types';
import { asArray } from '../utils/asArray';
import { findVirtualFoldersResult } from './findVirtualFoldersResult';
import { readAttr } from './readAttr';

export function parseVirtualFoldersXml(xml: string): {
  folders: VirtualFolderEntry[];
  objects: VirtualObjectEntry[];
} {
  const parsed = xmlParser.parse(xml) as NodeRecord;
  const root = findVirtualFoldersResult(parsed);
  if (!root) {
    throw new Error('Failed to parse virtual folders result');
  }
  const folderNodes = asArray(
    (root['vfs:virtualFolder'] as NodeRecord | NodeRecord[] | undefined) ||
      (root.virtualFolder as NodeRecord | NodeRecord[] | undefined),
  );
  const objectNodes = asArray(
    (root['vfs:object'] as NodeRecord | NodeRecord[] | undefined) ||
      (root.object as NodeRecord | NodeRecord[] | undefined),
  );

  return {
    folders: folderNodes.map((node) => ({
      name: readAttr(node, 'name'),
      displayName: readAttr(node, 'displayName'),
      facet: readAttr(node, 'facet'),
      text: readAttr(node, 'text'),
      type: readAttr(node, 'type'),
    })),
    objects: objectNodes.map((node) => ({
      name: readAttr(node, 'name'),
      type: readAttr(node, 'type'),
      text: readAttr(node, 'text'),
      packageName:
        readAttr(node, 'packageName') ||
        readAttr(node, 'package') ||
        readAttr(node, 'devclass') ||
        undefined,
    })),
  };
}
