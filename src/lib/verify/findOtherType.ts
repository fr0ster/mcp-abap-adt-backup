import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import { readMetadataXmlForType } from '../backup/readMetadataXmlForType';
import type { SupportedType } from '../types';

const supportedTypes: SupportedType[] = [
  'package',
  'domain',
  'dataElement',
  'structure',
  'table',
  'tableType',
  'ddl',
  'scalarFunction',
  'scalarFunctionImplementation',
  'class',
  'interface',
  'program',
  'transformation',
  'functionGroup',
  'serviceDefinition',
  'serviceBinding',
  'metadataExtension',
  'behaviorDefinition',
  'behaviorImplementation',
  'enhancement',
  'unitTest',
  'cdsUnitTest',
];

export async function findOtherType(
  client: AdtClient,
  expectedType: SupportedType,
  name: string,
): Promise<SupportedType | undefined> {
  for (const type of supportedTypes) {
    if (type === expectedType || type === 'functionModule') {
      continue;
    }
    try {
      const metadata = await readMetadataXmlForType(client, type, name);
      if (metadata) {
        return type;
      }
    } catch (_error) {
      // ignore and try next type
    }
  }
  return undefined;
}
