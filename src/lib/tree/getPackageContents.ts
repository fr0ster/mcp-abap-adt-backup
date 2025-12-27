import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import type { IAdtResponse } from '@mcp-abap-adt/interfaces';

export async function getPackageContents(
  client: AdtClient,
  packageName: string,
): Promise<IAdtResponse> {
  return await client.getUtils().getPackageContents(packageName);
}
