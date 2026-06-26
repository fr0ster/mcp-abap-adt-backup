import type { BackupConfig, SupportedType } from '../types';
import { applyConfigName } from '../utils/applyConfigName';
import { toBackupConfig } from '../utils/toBackupConfig';
import { extractMetadata } from '../xml/extractMetadata';
import { parseBehaviorDefinitionConfig } from '../xml/parseBehaviorDefinitionConfig';
import { parseClassConfig } from '../xml/parseClassConfig';
import { parseDataElementConfig } from '../xml/parseDataElementConfig';
import { parseDomainConfig } from '../xml/parseDomainConfig';
import { parseEnhancementConfig } from '../xml/parseEnhancementConfig';
import { parsePackageConfig } from '../xml/parsePackageConfig';
import { parseServiceBindingConfig } from '../xml/parseServiceBindingConfig';
import { parseTableTypeConfig } from '../xml/parseTableTypeConfig';

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
    case 'accessControl': {
      if (!metadataXml) {
        return undefined;
      }
      const { description, packageName } = extractMetadata(metadataXml);
      return applyConfigName(type, name, functionGroupName, {
        accessControlName: name,
        packageName,
        description,
      } as BackupConfig);
    }
    case 'serviceBinding': {
      if (!metadataXml) {
        return undefined;
      }
      const config = parseServiceBindingConfig(metadataXml);
      return applyConfigName(
        type,
        name,
        functionGroupName,
        toBackupConfig(config),
      );
    }
    case 'class': {
      if (!metadataXml) {
        return applyConfigName(type, name, functionGroupName, {});
      }
      const config = parseClassConfig(metadataXml);
      return applyConfigName(
        type,
        name,
        functionGroupName,
        toBackupConfig(config),
      );
    }
    case 'behaviorDefinition': {
      if (!metadataXml) {
        return applyConfigName(type, name, functionGroupName, {});
      }
      const config = parseBehaviorDefinitionConfig(metadataXml);
      return applyConfigName(
        type,
        name,
        functionGroupName,
        toBackupConfig(config),
      );
    }
    case 'enhancement': {
      if (!metadataXml) {
        return applyConfigName(type, name, functionGroupName, {});
      }
      const config = parseEnhancementConfig(metadataXml);
      return applyConfigName(
        type,
        name,
        functionGroupName,
        toBackupConfig(config),
      );
    }
    case 'tableType': {
      if (!metadataXml) {
        return applyConfigName(type, name, functionGroupName, {});
      }
      const config = parseTableTypeConfig(metadataXml);
      return applyConfigName(
        type,
        name,
        functionGroupName,
        toBackupConfig(config),
      );
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
