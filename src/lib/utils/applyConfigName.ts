import type { BackupConfig, SupportedType } from '../types';

export function applyConfigName(
  type: SupportedType,
  name: string,
  functionGroupName?: string,
  config?: BackupConfig,
): BackupConfig {
  const finalConfig = { ...(config || {}) };
  switch (type) {
    case 'package':
      finalConfig.packageName = name;
      break;
    case 'domain':
      finalConfig.domainName = name;
      break;
    case 'dataElement':
      finalConfig.dataElementName = name;
      break;
    case 'structure':
      finalConfig.structureName = name;
      break;
    case 'table':
      finalConfig.tableName = name;
      break;
    case 'tableType':
      finalConfig.tableTypeName = name;
      break;
    case 'view':
      finalConfig.viewName = name;
      break;
    case 'class':
      finalConfig.className = name;
      break;
    case 'interface':
      finalConfig.interfaceName = name;
      break;
    case 'program':
      finalConfig.programName = name;
      break;
    case 'transformation':
      finalConfig.transformationName = name;
      break;
    case 'functionGroup':
      finalConfig.functionGroupName = name;
      break;
    case 'functionModule':
      finalConfig.functionModuleName = name;
      finalConfig.functionGroupName = functionGroupName;
      break;
    case 'functionInclude':
      finalConfig.includeName = name;
      finalConfig.functionGroupName = functionGroupName;
      break;
    case 'serviceDefinition':
      finalConfig.serviceDefinitionName = name;
      break;
    case 'serviceBinding':
      finalConfig.bindingName = name;
      break;
    case 'metadataExtension':
      finalConfig.name = name;
      break;
    case 'behaviorDefinition':
      finalConfig.name = name;
      break;
    case 'behaviorImplementation':
      finalConfig.className = name;
      break;
    case 'enhancement':
      finalConfig.enhancementName = name;
      break;
    case 'accessControl':
      finalConfig.accessControlName = name;
      break;
    case 'unitTest':
      finalConfig.className = name;
      break;
    case 'cdsUnitTest':
      finalConfig.cdsName = name;
      break;
  }
  return finalConfig;
}
