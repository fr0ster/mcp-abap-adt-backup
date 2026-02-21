import type {
  AdtClient,
  IFunctionGroupConfig,
  IServiceDefinitionConfig,
} from '@mcp-abap-adt/adt-clients';
import type { BackupConfig, BackupObject, ObjectSpec } from '../types';
import { applyConfigName } from '../utils/applyConfigName';
import { objectId } from '../utils/objectId';
import { parseBehaviorDefinitionFromClass } from '../utils/parseBehaviorDefinitionFromClass';
import { toBackupConfig } from '../utils/toBackupConfig';
import { extractMetadata } from '../xml/extractMetadata';
import { parseDataElementConfig } from '../xml/parseDataElementConfig';
import { parseDomainConfig } from '../xml/parseDomainConfig';
import { parsePackageConfig } from '../xml/parsePackageConfig';
import { parseServiceBindingConfig } from '../xml/parseServiceBindingConfig';
import { readBasicMetadata } from './readBasicMetadata';
import { readMetadataXmlForType } from './readMetadataXmlForType';
import { readSourceText } from './readSourceText';

export async function backupObject(
  client: AdtClient,
  spec: ObjectSpec,
): Promise<BackupObject> {
  const id = objectId(spec);

  switch (spec.type) {
    case 'package': {
      const metadataXml = await readMetadataXmlForType(
        client,
        spec.type,
        spec.name,
      );
      if (!metadataXml) {
        throw new Error(`Package not found: ${spec.name}`);
      }
      const config = parsePackageConfig(metadataXml);
      return {
        id,
        type: spec.type,
        name: spec.name,
        config: applyConfigName(
          spec.type,
          spec.name,
          undefined,
          toBackupConfig(config),
        ),
      };
    }
    case 'domain': {
      const metadataXml = await readMetadataXmlForType(
        client,
        spec.type,
        spec.name,
      );
      if (!metadataXml) {
        throw new Error(`Domain not found: ${spec.name}`);
      }
      const config = parseDomainConfig(metadataXml);
      return {
        id,
        type: spec.type,
        name: spec.name,
        config: applyConfigName(
          spec.type,
          spec.name,
          undefined,
          toBackupConfig(config),
        ),
      };
    }
    case 'dataElement': {
      const metadataXml = await readMetadataXmlForType(
        client,
        spec.type,
        spec.name,
      );
      if (!metadataXml) {
        throw new Error(`Data element not found: ${spec.name}`);
      }
      const config = parseDataElementConfig(metadataXml);
      return {
        id,
        type: spec.type,
        name: spec.name,
        config: applyConfigName(
          spec.type,
          spec.name,
          undefined,
          toBackupConfig(config),
        ),
      };
    }
    case 'functionGroup': {
      const metadataXml = await readMetadataXmlForType(
        client,
        spec.type,
        spec.name,
      );
      if (!metadataXml) {
        throw new Error(`Function group not found: ${spec.name}`);
      }
      const metadata = extractMetadata(metadataXml);
      const config = {
        functionGroupName: spec.name,
        packageName: metadata.packageName,
        description: metadata.description,
      } as Partial<IFunctionGroupConfig>;
      return {
        id,
        type: spec.type,
        name: spec.name,
        config: applyConfigName(
          spec.type,
          spec.name,
          undefined,
          toBackupConfig(config),
        ),
      };
    }
    case 'serviceDefinition': {
      const metadataXml = await readMetadataXmlForType(
        client,
        spec.type,
        spec.name,
      );
      if (!metadataXml) {
        throw new Error(`Service definition not found: ${spec.name}`);
      }
      const metadata = extractMetadata(metadataXml);
      const config = {
        serviceDefinitionName: spec.name,
        packageName: metadata.packageName,
        description: metadata.description,
      } as Partial<IServiceDefinitionConfig>;
      const source = await readSourceText(client, spec);
      return {
        id,
        type: spec.type,
        name: spec.name,
        config: applyConfigName(
          spec.type,
          spec.name,
          undefined,
          toBackupConfig(config),
        ),
        source,
      };
    }
    case 'serviceBinding': {
      const metadataXml = await readMetadataXmlForType(
        client,
        spec.type,
        spec.name,
      );
      if (!metadataXml) {
        throw new Error(`Service binding not found: ${spec.name}`);
      }
      const config = parseServiceBindingConfig(metadataXml);
      return {
        id,
        type: spec.type,
        name: spec.name,
        config: applyConfigName(
          spec.type,
          spec.name,
          undefined,
          toBackupConfig(config),
        ),
      };
    }
    case 'metadataExtension':
    case 'behaviorDefinition': {
      const metadataXml = await readMetadataXmlForType(
        client,
        spec.type,
        spec.name,
      );
      const metadata = metadataXml ? extractMetadata(metadataXml) : {};
      const source = await readSourceText(client, spec);
      const config = applyConfigName(spec.type, spec.name, undefined, {
        description: metadata.description,
        packageName: metadata.packageName,
      });
      return {
        id,
        type: spec.type,
        name: spec.name,
        config,
        source,
      };
    }
    case 'behaviorImplementation':
    case 'enhancement': {
      const metadataXml = await readMetadataXmlForType(
        client,
        spec.type,
        spec.name,
      );
      const metadata = metadataXml ? extractMetadata(metadataXml) : {};
      const source = await readSourceText(client, spec);
      const config = applyConfigName(spec.type, spec.name, undefined, {
        description: metadata.description,
        packageName: metadata.packageName,
        ...(spec.type === 'behaviorImplementation' && source
          ? { behaviorDefinition: parseBehaviorDefinitionFromClass(source) }
          : {}),
      });
      return {
        id,
        type: spec.type,
        name: spec.name,
        config,
        source,
      };
    }
    case 'functionModule': {
      const basic = await readBasicMetadata(client, spec);
      const source = await readSourceText(client, spec);
      const config = applyConfigName(
        spec.type,
        spec.name,
        spec.functionGroupName,
        {
          functionGroupName: spec.functionGroupName,
          functionModuleName: spec.name,
          packageName: basic.packageName,
          description: basic.description,
        } as BackupConfig,
      );
      return {
        id,
        type: spec.type,
        name: spec.name,
        functionGroupName: spec.functionGroupName,
        config,
        source,
      };
    }
    default: {
      const basic = await readBasicMetadata(client, spec);
      const source = await readSourceText(client, spec);
      const config = applyConfigName(
        spec.type,
        spec.name,
        spec.functionGroupName,
        {
          packageName: basic.packageName,
          description: basic.description,
        } as BackupConfig,
      );
      return {
        id,
        type: spec.type,
        name: spec.name,
        config,
        source,
      };
    }
  }
}
