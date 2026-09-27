import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import { readMetadataXmlForType } from '../backup/readMetadataXmlForType';
import { readSourceText } from '../backup/readSourceText';
import { decodeBase64 } from '../crypto/decodeBase64';
import { canonicalizeMessageClass } from '../messageClass/canonicalizeMessageClass';
import { readMessageClass } from '../messageClass/readMessageClass';
import type { ParsedMessageClass } from '../messageClass/types';
import type { ObjectSpec } from '../types';
import { canonicalDocument } from '../xml/canonicalDocument';
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
    if (spec.type === 'messageClass') {
      const system = await readMessageClass(client, spec.name);
      if (!system) {
        return { ...base, status: 'missing' };
      }
      if (system.packageName) {
        base.actualPackage = system.packageName;
      }
      if (
        expectedPackage &&
        system.packageName &&
        system.packageName.toUpperCase() !== expectedPackage.toUpperCase()
      ) {
        return {
          ...base,
          status: 'package-mismatch',
          message: `Expected package ${expectedPackage}, found ${system.packageName}`,
        };
      }
      const expectedText =
        expectedSourceBase64 !== undefined
          ? decodeBase64(expectedSourceBase64)
          : expectedSource;
      if (expectedText !== undefined) {
        const expectedCls = JSON.parse(expectedText) as ParsedMessageClass;
        if (
          canonicalizeMessageClass(system) !==
          canonicalizeMessageClass(expectedCls)
        ) {
          return {
            ...base,
            status: 'source-mismatch',
            message: 'Message class content differs from backup',
          };
        }
      }
      return base;
    }

    // 1. Try to get metadata first (works for almost everything)
    const metadataXml = await readMetadataXmlForType(
      client,
      spec.type,
      spec.name,
      spec.functionGroupName,
    );

    if (metadataXml === null) {
      return { ...base, status: 'missing' };
    }

    if (metadataXml !== undefined) {
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

      // If we don't need source check, we're done
      if (!expectedSource && !expectedSourceBase64) {
        return base;
      }

      // A document-backed object (domain, data element, table type, …) is
      // compared by its definition; its package alone says nothing about the
      // row type, keys or value table a restore would write back.
      if (expectedFormat === 'xml' || spec.type === 'tableType') {
        const expectedXml =
          expectedSourceBase64 !== undefined
            ? decodeBase64(expectedSourceBase64)
            : (expectedSource as string);
        if (canonicalDocument(expectedXml) !== canonicalDocument(metadataXml)) {
          return {
            ...base,
            status: 'source-mismatch',
            message: 'Definition differs from backup',
          };
        }
        return base;
      }
    }

    // 2. Secondary check via Source (if required or metadata is unsupported)
    const actualSource = await readSourceText(client, spec, version);

    if (actualSource === null && metadataXml === undefined) {
      // If metadata was unsupported AND source is missing - it's missing
      return { ...base, status: 'missing' };
    }

    if (actualSource !== undefined) {
      const expectedText =
        expectedSourceBase64 !== undefined
          ? decodeBase64(expectedSourceBase64)
          : expectedSource;

      if (expectedText !== undefined && expectedFormat !== 'xml') {
        if (expectedText !== actualSource) {
          return {
            ...base,
            status: 'source-mismatch',
            message: 'Source differs from backup',
          };
        }
      }
    }

    return base;
  } catch (error: any) {
    return {
      ...base,
      status: 'error',
      message: error.message || String(error),
    };
  }
}
