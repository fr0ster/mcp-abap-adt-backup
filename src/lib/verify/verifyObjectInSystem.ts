import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import { readMetadataXmlForType } from '../backup/readMetadataXmlForType';
import { readSourceText } from '../backup/readSourceText';
import { decodeBase64 } from '../crypto/decodeBase64';
import type { ObjectSpec } from '../types';
import { extractMetadata } from '../xml/extractMetadata';
import { findOtherType } from './findOtherType';
import type { VerifyEntry } from './types';

export async function verifyObjectInSystem(
  client: AdtClient,
  spec: ObjectSpec,
  expectedPackage?: string,
  expectedSource?: string,
  expectedSourceBase64?: string,
): Promise<VerifyEntry> {
  const base: VerifyEntry = {
    type: spec.type,
    name: spec.name,
    functionGroupName: spec.functionGroupName,
    status: 'ok',
    expectedPackage,
  };

  let metadataXml: string | undefined;
  try {
    metadataXml = await readMetadataXmlForType(
      client,
      spec.type,
      spec.name,
      spec.functionGroupName,
    );
  } catch (error) {
    const otherType = await findOtherType(client, spec.type, spec.name);
    if (otherType) {
      return {
        ...base,
        status: 'type-mismatch',
        message: `Found object of type ${otherType}`,
      };
    }
    return {
      ...base,
      status: 'missing',
      message: error instanceof Error ? error.message : String(error),
    };
  }

  if (!metadataXml) {
    return {
      ...base,
      status: 'unsupported',
      message: 'Metadata read is not supported for this object type',
    };
  }

  const metadata = extractMetadata(metadataXml);
  if (metadata.packageName) {
    base.actualPackage = metadata.packageName;
  }

  if (
    expectedPackage &&
    metadata.packageName &&
    metadata.packageName.toUpperCase() !== expectedPackage.toUpperCase()
  ) {
    return {
      ...base,
      status: 'package-mismatch',
      message: `Expected package ${expectedPackage}, found ${metadata.packageName}`,
    };
  }

  const expectedText =
    expectedSourceBase64 !== undefined
      ? decodeBase64(expectedSourceBase64)
      : expectedSource;

  if (expectedText !== undefined) {
    try {
      const actualSource = await readSourceText(client, spec);
      if (actualSource !== undefined) {
        if (expectedText !== actualSource) {
          return {
            ...base,
            status: 'source-mismatch',
            message: 'Source differs from backup',
          };
        }
      }
    } catch (error) {
      return {
        ...base,
        status: 'error',
        message: error instanceof Error ? error.message : String(error),
      };
    }
  }

  return base;
}
