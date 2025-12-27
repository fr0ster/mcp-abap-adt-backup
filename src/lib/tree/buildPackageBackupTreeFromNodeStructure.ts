import * as fs from 'node:fs';
import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import { logVerbose } from '../cli/logVerbose';
import { xmlParser } from '../constants/xmlParser';
import type { BackupTreeFile } from '../types';
import { collectNodeObjects } from '../xml/collectNodeObjects';
import { findNodeByName } from '../xml/findNodeByName';
import { parseNodeTree } from '../xml/parseNodeTree';
import { enrichTreeNode } from './enrichTreeNode';
import { getPackageContents } from './getPackageContents';
import { stripVirtualGroups } from './stripVirtualGroups';

export async function buildPackageBackupTreeFromNodeStructure(
  client: AdtClient,
  packageName: string,
  includeCode: boolean,
): Promise<BackupTreeFile> {
  const packageNameUpper = packageName.toUpperCase();
  logVerbose(
    2,
    `Fetching package contents for ${packageNameUpper} (includeCode=${includeCode})`,
  );
  const response = await getPackageContents(client, packageNameUpper);
  const xml =
    typeof response.data === 'string'
      ? response.data
      : JSON.stringify(response.data);
  const parsed = xmlParser.parse(xml);
  const rootNodeObject =
    findNodeByName(parsed, packageNameUpper) || collectNodeObjects(parsed)[0];

  if (!rootNodeObject) {
    const fallbackPath = `/tmp/adt-backup-nodestructure-${packageNameUpper}.xml`;
    try {
      fs.writeFileSync(fallbackPath, xml, 'utf8');
    } catch (_error) {
      throw new Error(`Failed to parse package tree for ${packageNameUpper}`);
    }
    throw new Error(
      `Failed to parse package tree for ${packageNameUpper}. Raw response saved to ${fallbackPath}`,
    );
  }

  logVerbose(2, `Building node tree for ${packageNameUpper}`);
  const rootTree = parseNodeTree(rootNodeObject);
  const enrichedRoot = await enrichTreeNode(rootTree, client, includeCode);
  const trimmedRoot = stripVirtualGroups(enrichedRoot);

  return {
    schemaVersion: 2,
    generatedAt: new Date().toISOString(),
    package: packageNameUpper,
    root: trimmedRoot,
  };
}
