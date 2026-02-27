import type {
  AdtClient,
  IAccessControlConfig,
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
import { parsePackageConfig } from '../xml/parsePackageConfig';
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
  transportLayerOverride?: string,
): Promise<void> {
  if (mode === 'skip') {
    logVerbose(2, `  [SKIP] ${node.type}:${node.name}`);
    return;
  }

  if (!node.type || node.restoreStatus !== 'ok') {
    return;
  }

  // Use existing config or try to extract from XML if missing
  let nodeConfig = node.config;
  if (
    !nodeConfig &&
    node.codeBase64 &&
    node.codeFormat === 'xml' &&
    node.type === 'package'
  ) {
    try {
      const xml = decodeBase64(node.codeBase64);
      nodeConfig = parsePackageConfig(xml) as any;
    } catch (_e) {
      logVerbose(2, `  Could not parse XML config for package ${node.name}`);
    }
  }

  const config = applyTransportRequest(
    ensureDescription(nodeConfig || {}, node.name),
    transportRequest,
  );
  const payload = node.codeBase64 ? decodeBase64(node.codeBase64) : undefined;

  // Standard options for most objects
  const options = {
    activateOnCreate: activate,
    activateOnUpdate: activate,
  };

  try {
    switch (node.type) {
      case 'package': {
        const pkgConfig = asConfig<IPackageConfig>(config);

        if (!pkgConfig.packageName) {
          pkgConfig.packageName = node.name;
        }

        if (pkgConfig.responsible) {
          delete pkgConfig.responsible;
        }

        const superPackageInBackup =
          pkgConfig.superPackage &&
          backupPackageNames?.has(pkgConfig.superPackage);
        if (!superPackageInBackup && superPackageOverride) {
          pkgConfig.superPackage = superPackageOverride;
        }

        if (softwareComponentOverride) {
          pkgConfig.softwareComponent = softwareComponentOverride;
        } else if (!pkgConfig.softwareComponent) {
          pkgConfig.softwareComponent = 'ZLOCAL';
        }

        // Fix for the transport layer mapping issue in adt-clients
        if (transportLayerOverride) {
          pkgConfig.transportLayer = transportLayerOverride;
          (pkgConfig as any).transport_layer = transportLayerOverride;
        }

        pkgConfig.recordChanges = true;

        if (mode !== 'update') {
          if (!pkgConfig.superPackage && node.type === 'package') {
            throw new Error(
              `Package ${node.name} cannot be created: superPackage is missing.`,
            );
          }
          logVerbose(
            3,
            `  Creating package ${node.name} (Layer: ${pkgConfig.transportLayer}, SoftwareComp: ${pkgConfig.softwareComponent})`,
          );
          await client.getPackage().create(pkgConfig, options);
          // Wait for SAP to commit the package to the database
          // ADT has no event subscription for creation completion
          await delay(2000);
        }
        if (mode !== 'create') {
          try {
            await client.getPackage().update(pkgConfig, options);
          } catch (error) {
            const msg = error instanceof Error ? error.message : String(error);
            logVerbose(1, `  [SKIP] Package ${node.name} update skipped`);
            logVerbose(3, `    Reason: ${msg.slice(0, 200)}`);
          }
        }
        return;
      }
      case 'domain': {
        if (mode !== 'update') {
          await client
            .getDomain()
            .create(asConfig<IDomainConfig>(config), options);
        }
        // Always update to set datatype/length/decimals (create only registers the name)
        await client
          .getDomain()
          .update(asConfig<IDomainConfig>(config), options);
        return;
      }
      case 'dataElement': {
        if (mode !== 'update') {
          await client
            .getDataElement()
            .create(asConfig<IDataElementConfig>(config), options);
        }
        // Always update to set typeKind/typeName/dataType (create only registers the name)
        await client
          .getDataElement()
          .update(asConfig<IDataElementConfig>(config), options);
        return;
      }
      case 'structure': {
        if (mode !== 'update') {
          await client
            .getStructure()
            .create(asConfig<IStructureConfig>(config), options);
        }
        if (payload) {
          await client.getStructure().update(
            asConfig<IStructureConfig>({
              ...config,
              ddlCode: payload,
            }),
            options,
          );
        }
        return;
      }
      case 'table': {
        if (mode !== 'update') {
          await client
            .getTable()
            .create(asConfig<ITableConfig>(config), options);
        }
        if (payload) {
          await client
            .getTable()
            .update(
              asConfig<ITableConfig>({ ...config, ddlCode: payload }),
              options,
            );
        }
        return;
      }
      case 'view': {
        if (mode !== 'update') {
          await client.getView().create(asConfig<IViewConfig>(config), options);
        }
        if (payload) {
          await client
            .getView()
            .update(
              asConfig<IViewConfig>({ ...config, ddlSource: payload }),
              options,
            );
        }
        return;
      }
      case 'class': {
        if (mode !== 'update') {
          await client
            .getClass()
            .create(asConfig<IClassConfig>(config), options);
        }
        if (payload) {
          await client.getClass().update(
            asConfig<IClassConfig>({
              ...config,
              sourceCode: payload,
            }),
            options,
          );
        }
        return;
      }
      case 'interface': {
        if (mode !== 'update') {
          await client
            .getInterface()
            .create(asConfig<IInterfaceConfig>(config), options);
        }
        if (payload) {
          await client.getInterface().update(
            asConfig<IInterfaceConfig>({
              ...config,
              sourceCode: payload,
            }),
            options,
          );
        }
        return;
      }
      case 'program': {
        if (mode !== 'update') {
          await client
            .getProgram()
            .create(asConfig<IProgramConfig>(config), options);
        }
        if (payload) {
          await client.getProgram().update(
            asConfig<IProgramConfig>({
              ...config,
              sourceCode: payload,
            }),
            options,
          );
        }
        return;
      }
      case 'functionGroup': {
        if (mode !== 'update') {
          await client
            .getFunctionGroup()
            .create(asConfig<IFunctionGroupConfig>(config), options);
        }
        // Always update to set properties (create only registers the name)
        await client
          .getFunctionGroup()
          .update(asConfig<IFunctionGroupConfig>(config), options);
        return;
      }
      case 'functionModule': {
        if (mode !== 'update') {
          await client
            .getFunctionModule()
            .create(asConfig<IFunctionModuleConfig>(config), options);
        }
        if (payload) {
          await client.getFunctionModule().update(
            asConfig<IFunctionModuleConfig>({
              ...config,
              sourceCode: payload,
            }),
            options,
          );
        }
        return;
      }
      case 'serviceDefinition': {
        if (mode !== 'update') {
          await client
            .getServiceDefinition()
            .create(asConfig<IServiceDefinitionConfig>(config), options);
        }
        if (payload) {
          await client.getServiceDefinition().update(
            asConfig<IServiceDefinitionConfig>({
              ...config,
              sourceCode: payload,
            }),
            options,
          );
        }
        return;
      }
      case 'serviceBinding': {
        if (mode !== 'update') {
          await client
            .getServiceBinding()
            .create(asConfig<IServiceBindingConfig>(config), options);
        }
        // Always update to set properties (create only registers the name)
        await client
          .getServiceBinding()
          .update(asConfig<IServiceBindingConfig>(config));
        return;
      }
      case 'metadataExtension': {
        if (mode !== 'update') {
          await client
            .getMetadataExtension()
            .create(asConfig<IMetadataExtensionConfig>(config), options);
        }
        if (payload) {
          await client.getMetadataExtension().update(
            asConfig<IMetadataExtensionConfig>({
              ...config,
              sourceCode: payload,
            }),
            options,
          );
        }
        return;
      }
      case 'behaviorDefinition': {
        if (mode !== 'update') {
          await client
            .getBehaviorDefinition()
            .create(asConfig<IBehaviorDefinitionConfig>(config), options);
        }
        if (payload) {
          await client.getBehaviorDefinition().update(
            asConfig<IBehaviorDefinitionConfig>({
              ...config,
              sourceCode: payload,
            }),
            options,
          );
        }
        return;
      }
      case 'behaviorImplementation': {
        if (mode !== 'update') {
          await client
            .getBehaviorImplementation()
            .create(asConfig<IBehaviorImplementationConfig>(config), options);
        }
        if (payload) {
          await client.getBehaviorImplementation().update(
            asConfig<IBehaviorImplementationConfig>({
              ...config,
              sourceCode: payload,
            }),
            options,
          );
        }
        return;
      }
      case 'enhancement': {
        if (mode !== 'update') {
          await client
            .getEnhancement()
            .create(asConfig<IEnhancementConfig>(config), options);
        }
        if (payload) {
          await client.getEnhancement().update(
            asConfig<IEnhancementConfig>({
              ...config,
              sourceCode: payload,
            }),
            options,
          );
        }
        return;
      }
      case 'accessControl': {
        if (mode !== 'update') {
          await client
            .getAccessControl()
            .create(asConfig<IAccessControlConfig>(config), options);
        }
        if (payload) {
          await client.getAccessControl().update(
            asConfig<IAccessControlConfig>({
              ...config,
              sourceCode: payload,
            }),
            options,
          );
        }
        return;
      }
      case 'tableType': {
        if (mode !== 'update') {
          await client
            .getTableType()
            .create(asConfig<ITableTypeConfig>(config), options);
        }
        // Always update to set properties (create only registers the name)
        await client
          .getTableType()
          .update(asConfig<ITableTypeConfig>(config), options);
        return;
      }
    }
  } catch (error: any) {
    const data = error.response?.data;
    if (data) {
      const errorMsg =
        typeof data === 'string' ? data : JSON.stringify(data, null, 2);
      console.error(`Error restoring ${node.type}:${node.name}:\n${errorMsg}`);
    }
    throw error;
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
