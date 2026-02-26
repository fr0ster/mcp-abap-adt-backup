import type {
  AdtClient,
  IBehaviorDefinitionConfig,
  IBehaviorImplementationConfig,
  IClassConfig,
  IDataElementConfig,
  IDomainConfig,
  IEnhancementConfig,
  IFunctionGroupConfig,
  IFunctionModuleConfig,
  IInterfaceConfig,
  IMetadataExtensionConfig,
  IPackageConfig,
  IProgramConfig,
  IServiceBindingConfig,
  IServiceDefinitionConfig,
  IStructureConfig,
  ITableConfig,
  ITableTypeConfig,
  IViewConfig,
} from '@mcp-abap-adt/adt-clients';
import { logVerbose } from '../cli/logVerbose';
import { decodeBase64 } from '../crypto/decodeBase64';
import type { BackupTreeNode, RestoreMode } from '../types';
import { asConfig } from '../utils/asConfig';
import { ensureDescription } from '../utils/ensureDescription';
import { applyTransportRequest } from './applyTransportRequest';

export async function restoreTreeNode(
  client: AdtClient,
  node: BackupTreeNode,
  mode: RestoreMode,
  activate: boolean,
  transportRequest?: string,
  softwareComponentOverride?: string,
  backupPackageNames?: Set<string>,
  superPackageOverride?: string,
): Promise<void> {
  if (!node.type || node.restoreStatus !== 'ok') {
    return;
  }

  // Configuration for the object
  const config = applyTransportRequest(
    ensureDescription(node.config || {}, node.name),
    transportRequest,
  );
  
  const payload = node.codeBase64 ? decodeBase64(node.codeBase64) : undefined;
  const options = {
    activateOnCreate: activate,
    activateOnUpdate: activate,
  };

  try {
    switch (node.type) {
      case 'package': {
        const pkgConfig = asConfig<IPackageConfig>(config);

        // Basic package info
        if (!pkgConfig.packageName) pkgConfig.packageName = node.name;
        if (pkgConfig.responsible) delete pkgConfig.responsible;

        // Hierarchy logic:
        // Use hierarchy parent name (superPackageOverride) IF current superPackage is missing
        // or NOT in the backup (meaning it's the root of our backup).
        const currentSuperInBackup = pkgConfig.superPackage && backupPackageNames?.has(pkgConfig.superPackage);
        
        if (!currentSuperInBackup && superPackageOverride) {
          pkgConfig.superPackage = superPackageOverride;
        }

        // Apply software component
        if (softwareComponentOverride) {
          pkgConfig.softwareComponent = softwareComponentOverride;
        } else if (!pkgConfig.softwareComponent) {
          pkgConfig.softwareComponent = 'ZLOCAL';
        }

        if (mode !== 'update') {
          // If we are CREATING a package, SAP strictly requires a superPackage.
          if (!pkgConfig.superPackage) {
            throw new Error(`Package ${node.name} cannot be created: Super package is missing in backup and no --super-package provided. Please create the package manually in SAP or specify its parent.`);
          }
          await client.getPackage().create(pkgConfig, options);
        }
        
        if (mode !== 'create') {
          await client.getPackage().update(pkgConfig, options);
        }
        return;
      }
      case 'domain': {
        if (mode !== 'update') {
          await client.getDomain().create(asConfig<IDomainConfig>(config), options);
        }
        if (mode !== 'create') {
          await client.getDomain().update(asConfig<IDomainConfig>(config), options);
        }
        return;
      }
      case 'dataElement': {
        if (mode !== 'update') {
          await client.getDataElement().create(asConfig<IDataElementConfig>(config), options);
        }
        if (mode !== 'create') {
          await client.getDataElement().update(asConfig<IDataElementConfig>(config), options);
        }
        return;
      }
      case 'structure': {
        if (mode !== 'update') {
          await client.getStructure().create(asConfig<IStructureConfig>(config), options);
        }
        if (payload) {
          await client.getStructure().update(asConfig<IStructureConfig>({ ...config, ddlCode: payload }), options);
        }
        return;
      }
      case 'table': {
        if (mode !== 'update') {
          await client.getTable().create(asConfig<ITableConfig>(config), options);
        }
        if (payload) {
          await client.getTable().update(asConfig<ITableConfig>({ ...config, ddlCode: payload }), options);
        }
        return;
      }
      case 'view': {
        if (mode !== 'update') {
          await client.getView().create(asConfig<IViewConfig>(config), options);
        }
        if (payload) {
          await client.getView().update(asConfig<IViewConfig>({ ...config, ddlSource: payload }), options);
        }
        return;
      }
      case 'class': {
        if (mode !== 'update') {
          await client.getClass().create(asConfig<IClassConfig>(config), options);
        }
        if (payload) {
          await client.getClass().update(asConfig<IClassConfig>({ ...config, sourceCode: payload }), options);
        }
        return;
      }
      case 'interface': {
        if (mode !== 'update') {
          await client.getInterface().create(asConfig<IInterfaceConfig>(config), options);
        }
        if (payload) {
          await client.getInterface().update(asConfig<IInterfaceConfig>({ ...config, sourceCode: payload }), options);
        }
        return;
      }
      case 'program': {
        if (mode !== 'update') {
          await client.getProgram().create(asConfig<IProgramConfig>(config), options);
        }
        if (payload) {
          await client.getProgram().update(asConfig<IProgramConfig>({ ...config, sourceCode: payload }), options);
        }
        return;
      }
      case 'functionGroup': {
        if (mode !== 'update') {
          await client.getFunctionGroup().create(asConfig<IFunctionGroupConfig>(config), options);
        }
        if (mode !== 'create') {
          await client.getFunctionGroup().update(asConfig<IFunctionGroupConfig>(config), options);
        }
        return;
      }
      case 'functionModule': {
        if (mode !== 'update') {
          await client.getFunctionModule().create(asConfig<IFunctionModuleConfig>(config), options);
        }
        if (payload) {
          await client.getFunctionModule().update(asConfig<IFunctionModuleConfig>({ ...config, sourceCode: payload }), options);
        }
        return;
      }
      case 'serviceDefinition': {
        if (mode !== 'update') {
          await client.getServiceDefinition().create(asConfig<IServiceDefinitionConfig>(config), options);
        }
        if (payload) {
          await client.getServiceDefinition().update(asConfig<IServiceDefinitionConfig>({ ...config, sourceCode: payload }), options);
        }
        return;
      }
      case 'serviceBinding': {
        if (mode !== 'update') {
          await client.getServiceBinding().create(asConfig<IServiceBindingConfig>(config), options);
        }
        if (mode !== 'create') {
          await client.getServiceBinding().update(asConfig<IServiceBindingConfig>(config));
        }
        return;
      }
      case 'metadataExtension': {
        if (mode !== 'update') {
          await client.getMetadataExtension().create(asConfig<IMetadataExtensionConfig>(config), options);
        }
        if (payload) {
          await client.getMetadataExtension().update(asConfig<IMetadataExtensionConfig>({ ...config, sourceCode: payload }), options);
        }
        return;
      }
      case 'behaviorDefinition': {
        if (mode !== 'update') {
          await client.getBehaviorDefinition().create(asConfig<IBehaviorDefinitionConfig>(config), options);
        }
        if (payload) {
          await client.getBehaviorDefinition().update(asConfig<IBehaviorDefinitionConfig>({ ...config, sourceCode: payload }), options);
        }
        return;
      }
      case 'behaviorImplementation': {
        if (mode !== 'update') {
          await client.getBehaviorImplementation().create(asConfig<IBehaviorImplementationConfig>(config), options);
        }
        if (payload) {
          await client.getBehaviorImplementation().update(asConfig<IBehaviorImplementationConfig>({ ...config, sourceCode: payload }), options);
        }
        return;
      }
      case 'enhancement': {
        if (mode !== 'update') {
          await client.getEnhancement().create(asConfig<IEnhancementConfig>(config), options);
        }
        if (payload) {
          await client.getEnhancement().update(asConfig<IEnhancementConfig>({ ...config, sourceCode: payload }), options);
        }
        return;
      }
      case 'tableType': {
        if (mode !== 'update') {
          await client.getTableType().create(asConfig<ITableTypeConfig>(config), options);
        }
        if (mode !== 'create') {
          await client.getTableType().update(asConfig<ITableTypeConfig>(config), options);
        }
        return;
      }
    }
  } catch (error: any) {
    const data = error.response?.data;
    if (data) {
      const errorMsg = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
      console.error(`Error restoring ${node.type}:${node.name}:\n${errorMsg}`);
    }
    throw error;
  }
}
