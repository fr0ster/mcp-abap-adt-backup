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
  ITransformationConfig,
  IViewConfig,
} from '@mcp-abap-adt/adt-clients';
import type { BackupObject, RestoreMode } from '../types';
import { applyConfigName } from '../utils/applyConfigName';
import { asConfig } from '../utils/asConfig';
import { detectTransformationType } from '../utils/detectTransformationType';
import { ensureDescription } from '../utils/ensureDescription';
import { applyTransportRequest } from './applyTransportRequest';

export async function restoreObject(
  client: AdtClient,
  obj: BackupObject,
  mode: RestoreMode,
  activate: boolean,
  transportRequest?: string,
): Promise<void> {
  const baseConfig = applyConfigName(
    obj.type,
    obj.name,
    obj.functionGroupName,
    obj.config,
  );
  const config = applyTransportRequest(
    ensureDescription(baseConfig, obj.name),
    transportRequest,
  );

  const options = {
    activateOnCreate: activate,
    activateOnUpdate: activate,
  };

  switch (obj.type) {
    case 'package': {
      if (mode !== 'update') {
        await client
          .getPackage()
          .create(asConfig<IPackageConfig>(config), options);
      }
      if (mode !== 'create') {
        await client
          .getPackage()
          .update(asConfig<IPackageConfig>(config), options);
      }
      return;
    }
    case 'domain': {
      if (mode !== 'update') {
        await client
          .getDomain()
          .create(asConfig<IDomainConfig>(config), options);
      }
      if (mode !== 'create') {
        await client
          .getDomain()
          .update(asConfig<IDomainConfig>(config), options);
      }
      return;
    }
    case 'dataElement': {
      if (mode !== 'update') {
        await client
          .getDataElement()
          .create(asConfig<IDataElementConfig>(config), options);
      }
      if (mode !== 'create') {
        await client
          .getDataElement()
          .update(asConfig<IDataElementConfig>(config), options);
      }
      return;
    }
    case 'structure': {
      if (mode !== 'update') {
        await client
          .getStructure()
          .create(asConfig<IStructureConfig>(config), options);
      }
      if (obj.source) {
        await client.getStructure().update(
          asConfig<IStructureConfig>({
            ...config,
            ddlCode: obj.source,
          }),
          options,
        );
      }
      return;
    }
    case 'table': {
      if (mode !== 'update') {
        await client.getTable().create(asConfig<ITableConfig>(config), options);
      }
      if (obj.source) {
        await client
          .getTable()
          .update(
            asConfig<ITableConfig>({ ...config, ddlCode: obj.source }),
            options,
          );
      }
      return;
    }
    case 'view': {
      if (mode !== 'update') {
        await client.getView().create(asConfig<IViewConfig>(config), options);
      }
      if (obj.source) {
        await client
          .getView()
          .update(
            asConfig<IViewConfig>({ ...config, ddlSource: obj.source }),
            options,
          );
      }
      return;
    }
    case 'class': {
      if (mode !== 'update') {
        await client.getClass().create(asConfig<IClassConfig>(config), options);
      }
      if (obj.source) {
        await client.getClass().update(
          asConfig<IClassConfig>({
            ...config,
            sourceCode: obj.source,
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
      if (obj.source) {
        await client.getInterface().update(
          asConfig<IInterfaceConfig>({
            ...config,
            sourceCode: obj.source,
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
      if (obj.source) {
        await client.getProgram().update(
          asConfig<IProgramConfig>({
            ...config,
            sourceCode: obj.source,
          }),
          options,
        );
      }
      return;
    }
    case 'transformation': {
      const transformationType = detectTransformationType(obj.source);
      const baseTxConfig = {
        ...config,
        transformationType,
      };
      if (mode !== 'update') {
        await client
          .getTransformation()
          .create(asConfig<ITransformationConfig>(baseTxConfig), options);
      }
      if (obj.source) {
        await client.getTransformation().update(
          asConfig<ITransformationConfig>({
            ...baseTxConfig,
            sourceCode: obj.source,
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
      if (mode !== 'create') {
        await client
          .getFunctionGroup()
          .update(asConfig<IFunctionGroupConfig>(config), options);
      }
      return;
    }
    case 'functionModule': {
      if (mode !== 'update') {
        await client
          .getFunctionModule()
          .create(asConfig<IFunctionModuleConfig>(config), options);
      }
      if (obj.source) {
        await client.getFunctionModule().update(
          asConfig<IFunctionModuleConfig>({
            ...config,
            sourceCode: obj.source,
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
      if (obj.source) {
        await client.getServiceDefinition().update(
          asConfig<IServiceDefinitionConfig>({
            ...config,
            sourceCode: obj.source,
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
      if (mode !== 'create') {
        await client
          .getServiceBinding()
          .update(asConfig<IServiceBindingConfig>(config));
      }
      return;
    }
    case 'metadataExtension': {
      if (mode !== 'update') {
        await client
          .getMetadataExtension()
          .create(asConfig<IMetadataExtensionConfig>(config), options);
      }
      if (obj.source) {
        await client.getMetadataExtension().update(
          asConfig<IMetadataExtensionConfig>({
            ...config,
            sourceCode: obj.source,
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
      if (obj.source) {
        await client.getBehaviorDefinition().update(
          asConfig<IBehaviorDefinitionConfig>({
            ...config,
            sourceCode: obj.source,
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
      if (obj.source) {
        await client.getBehaviorImplementation().update(
          asConfig<IBehaviorImplementationConfig>({
            ...config,
            sourceCode: obj.source,
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
      if (obj.source) {
        await client.getEnhancement().update(
          asConfig<IEnhancementConfig>({
            ...config,
            sourceCode: obj.source,
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
      if (mode !== 'create') {
        await client
          .getTableType()
          .update(asConfig<ITableTypeConfig>(config), options);
      }
      return;
    }
  }
}
