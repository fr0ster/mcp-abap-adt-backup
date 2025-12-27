import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import type { VirtualFolderEntry, VirtualObjectEntry } from '../types';
import { parseVirtualFoldersXml } from '../xml/parseVirtualFoldersXml';

export async function fetchVirtualFolders(
  client: AdtClient,
  params: {
    objectSearchPattern?: string;
    preselection?: { facet: string; values: string[] }[];
    facetOrder?: string[];
    withVersions?: boolean;
    ignoreShortDescriptions?: boolean;
  },
): Promise<{ folders: VirtualFolderEntry[]; objects: VirtualObjectEntry[] }> {
  const response = await client.getUtils().getVirtualFoldersContents(params);
  const xml =
    typeof response.data === 'string'
      ? response.data
      : JSON.stringify(response.data);
  return parseVirtualFoldersXml(xml);
}
