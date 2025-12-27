import type { BackupConfig, SupportedType } from '../types';
import { applyConfigName } from '../utils/applyConfigName';
import { toBackupConfig } from '../utils/toBackupConfig';
import { extractMetadata } from '../xml/extractMetadata';
import { parseDataElementConfig } from '../xml/parseDataElementConfig';
import { parseDomainConfig } from '../xml/parseDomainConfig';
import { parsePackageConfig } from '../xml/parsePackageConfig';

export async function buildConfigForNode(
  type: SupportedType,
  name: string,
  functionGroupName: string | undefined,
  metadataXml?: string,
): Promise<BackupConfig | undefined> {
  switch (type) {
    case 'package': {
      if (!metadataXml) {
        return undefined;
      }
      const config = parsePackageConfig(metadataXml);
      return applyConfigName(
        type,
        name,
        functionGroupName,
        toBackupConfig(config),
      );
    }
    case 'domain': {
      if (!metadataXml) {
        return undefined;
      }
      const config = parseDomainConfig(metadataXml);
      return applyConfigName(
        type,
        name,
        functionGroupName,
        toBackupConfig(config),
      );
    }
    case 'dataElement': {
      if (!metadataXml) {
        return undefined;
      }
      const config = parseDataElementConfig(metadataXml);
      return applyConfigName(
        type,
        name,
        functionGroupName,
        toBackupConfig(config),
      );
    }
    case 'functionGroup': {
      if (!metadataXml) {
        return undefined;
      }
      const { description, packageName } = extractMetadata(metadataXml);
      return applyConfigName(type, name, functionGroupName, {
        functionGroupName: name,
        packageName,
        description,
      } as BackupConfig);
    }
    case 'functionModule': {
      if (!functionGroupName) {
        return applyConfigName(type, name, functionGroupName, {});
      }
      const config = applyConfigName(type, name, functionGroupName, {
        functionGroupName,
        functionModuleName: name,
      });
      if (!metadataXml) {
        return config;
      }
      const { description, packageName } = extractMetadata(metadataXml);
      return applyConfigName(type, name, functionGroupName, {
        ...config,
        description,
        packageName,
      });
    }
    case 'serviceDefinition': {
      if (!metadataXml) {
        return undefined;
      }
      const { description, packageName } = extractMetadata(metadataXml);
      return applyConfigName(type, name, functionGroupName, {
        serviceDefinitionName: name,
        packageName,
        description,
      } as BackupConfig);
    }
    default: {
      if (!metadataXml) {
        return applyConfigName(type, name, functionGroupName, {});
      }
      const { description, packageName } = extractMetadata(metadataXml);
      return applyConfigName(type, name, functionGroupName, {
        description,
        packageName,
      });
    }
  }
}
