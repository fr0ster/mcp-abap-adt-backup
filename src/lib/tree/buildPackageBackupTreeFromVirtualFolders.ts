import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import { logVerbose } from '../cli/logVerbose';
import type { BackupTreeFile, BackupTreeNode } from '../types';
import { enrichTreeNode } from './enrichTreeNode';
import { fetchVirtualFolders } from './fetchVirtualFolders';
import { groupTreeByPackage } from './groupTreeByPackage';

export async function buildPackageBackupTreeFromVirtualFolders(
  client: AdtClient,
  packageName: string,
  includeCode: boolean,
): Promise<BackupTreeFile> {
  const packageNameUpper = packageName.toUpperCase();
  const rootTree: BackupTreeNode = {
    name: packageNameUpper,
    adtType: 'DEVC/K',
    restoreStatus: 'not-implemented',
    children: [],
  };

  logVerbose(2, `Fetching virtual folders for ${packageNameUpper}`);

  const baseSelection = [{ facet: 'PACKAGE', values: [packageNameUpper] }];
  const groupResult = await fetchVirtualFolders(client, {
    objectSearchPattern: '*',
    preselection: baseSelection,
    facetOrder: ['GROUP'],
  });
  const groups = groupResult.folders.filter(
    (entry) => entry.facet?.toUpperCase() === 'GROUP',
  );

  for (const group of groups) {
    const groupSelection = group.name || group.displayName || 'GROUP';
    const groupLabel = group.displayName || group.name || 'GROUP';
    const groupNode: BackupTreeNode = {
      name: groupLabel,
      description: groupLabel !== groupSelection ? groupSelection : undefined,
      restoreStatus: 'not-implemented',
      children: [],
    };

    const typeResult = await fetchVirtualFolders(client, {
      objectSearchPattern: '*',
      preselection: [
        ...baseSelection,
        { facet: 'GROUP', values: [groupSelection] },
      ],
      facetOrder: ['TYPE'],
    });
    const types = typeResult.folders.filter(
      (entry) => entry.facet?.toUpperCase() === 'TYPE',
    );

    for (const type of types) {
      const typeSelection = type.name || type.displayName || 'TYPE';
      const typeLabel = type.displayName || type.name || 'TYPE';
      const typeNode: BackupTreeNode = {
        name: typeLabel,
        description: typeLabel !== typeSelection ? typeSelection : undefined,
        restoreStatus: 'not-implemented',
        children: [],
      };

      const objectResult = await fetchVirtualFolders(client, {
        objectSearchPattern: '*',
        preselection: [
          ...baseSelection,
          { facet: 'GROUP', values: [groupSelection] },
          { facet: 'TYPE', values: [typeSelection] },
        ],
        facetOrder: [],
      });

      typeNode.children = objectResult.objects
        .filter((entry) => entry.name)
        .map((entry) => ({
          name: entry.name || '',
          adtType: entry.type,
          description: entry.text,
          restoreStatus: 'not-implemented',
          children: [],
        }));

      groupNode.children?.push(typeNode);
    }

    rootTree.children?.push(groupNode);
  }

  logVerbose(2, `Building node tree for ${packageNameUpper}`);
  const enrichedRoot = await enrichTreeNode(rootTree, client, includeCode);
  const finalRoot = includeCode
    ? groupTreeByPackage(enrichedRoot)
    : enrichedRoot;

  return {
    schemaVersion: 2,
    generatedAt: new Date().toISOString(),
    package: packageNameUpper,
    root: finalRoot,
  };
}
