import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import { readMetadataXmlForType } from '../backup/readMetadataXmlForType';
import { readSourceText } from '../backup/readSourceText';
import { decodeBase64 } from '../crypto/decodeBase64';
import type { ObjectSpec } from '../types';
import { extractMetadata } from '../xml/extractMetadata';
import type { VerifyEntry } from './types';

export async function verifyObjectInSystem(
  client: AdtClient,
  spec: ObjectSpec,
  expectedPackage?: string,
  expectedSource?: string,
  expectedSourceBase64?: string,
  expectedFormat?: 'source' | 'xml' | 'json',
  version: 'active' | 'inactive' = 'active',
): Promise<VerifyEntry> {
  const base: VerifyEntry = {
    type: spec.type,
    name: spec.name,
    functionGroupName: spec.functionGroupName,
    status: 'ok',
    expectedPackage,
  };

  try {
    // If format is XML, we check metadata (e.g. for Domain, DataElement, Package)
    if (expectedFormat === 'xml' || spec.type === 'package' || spec.type === 'domain' || spec.type === 'dataElement' || spec.type === 'functionGroup') {
      const metadataXml = await readMetadataXmlForType(client, spec.type, spec.name, spec.functionGroupName);
      
      if (metadataXml === null) return { ...base, status: 'missing' };
      if (metadataXml === undefined) return { ...base, status: 'unsupported', message: 'Metadata check not supported' };

      const metadata = extractMetadata(metadataXml);
      if (metadata.packageName) base.actualPackage = metadata.packageName;

      if (expectedPackage && metadata.packageName && metadata.packageName.toUpperCase() !== expectedPackage.toUpperCase()) {
        return { ...base, status: 'package-mismatch', message: `Expected package ${expectedPackage}, found ${metadata.packageName}` };
      }
      return base;
    } 
    
    // If format is Source or unknown, we check existence via Source (e.g. for Class, View, BDEF)
    const actualSource = await readSourceText(client, spec, version);
    
    if (actualSource === null) return { ...base, status: 'missing' };
    
    // For source objects, we might also want to know the package, so we try metadata as a secondary check
    try {
      const metaXml = await readMetadataXmlForType(client, spec.type, spec.name, spec.functionGroupName);
      if (metaXml) {
        const metadata = extractMetadata(metaXml);
        if (metadata.packageName) base.actualPackage = metadata.packageName;
        if (expectedPackage && metadata.packageName && metadata.packageName.toUpperCase() !== expectedPackage.toUpperCase()) {
          return { ...base, status: 'package-mismatch', message: `Expected package ${expectedPackage}, found ${metadata.packageName}` };
        }
      }
    } catch (e) {
      // Ignore metadata failure for source-only objects
    }

    const expectedText = expectedSourceBase64 !== undefined ? decodeBase64(expectedSourceBase64) : expectedSource;
    if (expectedText !== undefined && actualSource !== undefined && expectedText !== actualSource) {
      return { ...base, status: 'source-mismatch', message: 'Source differs from backup' };
    }

    return base;
  } catch (error: any) {
    return { ...base, status: 'error', message: error.message || String(error) };
  }
}
