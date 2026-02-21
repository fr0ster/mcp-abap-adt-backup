import type { IServiceBindingConfig } from '@mcp-abap-adt/adt-clients';
import { xmlParser } from '../constants/xmlParser';
import type { NodeValue } from '../types';
import { findAttribute } from './findAttribute';
import { findNode } from './findNode';
import { getNodeAttribute } from './getNodeAttribute';

export function parseServiceBindingConfig(
  xml: string,
): Partial<IServiceBindingConfig> {
  const parsed = xmlParser.parse(xml) as NodeValue;
  const root =
    findNode(parsed, ['srvb:serviceBinding', 'serviceBinding']) ?? parsed;

  const bindingName =
    getNodeAttribute(root, 'adtcore:name') ||
    findAttribute(root, 'adtcore:name');
  const description =
    getNodeAttribute(root, 'adtcore:description') ||
    findAttribute(root, 'adtcore:description');
  const responsible =
    getNodeAttribute(root, 'adtcore:responsible') ||
    findAttribute(root, 'adtcore:responsible');
  const masterSystem =
    getNodeAttribute(root, 'adtcore:masterSystem') ||
    findAttribute(root, 'adtcore:masterSystem');
  const masterLanguage =
    getNodeAttribute(root, 'adtcore:masterLanguage') ||
    findAttribute(root, 'adtcore:masterLanguage') ||
    getNodeAttribute(root, 'adtcore:language') ||
    findAttribute(root, 'adtcore:language');

  const packageRef = findNode(root, ['adtcore:packageRef', 'packageRef']);
  const packageName =
    getNodeAttribute(packageRef, 'adtcore:name') ||
    findAttribute(packageRef, 'adtcore:name');

  const services = findNode(root, ['srvb:services', 'services']);
  const serviceName =
    getNodeAttribute(services, 'srvb:name') ||
    findAttribute(services, 'srvb:name');

  const content = findNode(services, ['srvb:content', 'content']);
  const serviceVersion =
    getNodeAttribute(content, 'srvb:version') ||
    findAttribute(content, 'srvb:version');

  const serviceDefinition = findNode(content, [
    'srvb:serviceDefinition',
    'serviceDefinition',
  ]);
  const serviceDefinitionName =
    getNodeAttribute(serviceDefinition, 'adtcore:name') ||
    findAttribute(serviceDefinition, 'adtcore:name');

  const binding = findNode(root, ['srvb:binding', 'binding']);
  const bindingType =
    getNodeAttribute(binding, 'srvb:type') ||
    findAttribute(binding, 'srvb:type');
  const bindingVersion =
    getNodeAttribute(binding, 'srvb:version') ||
    findAttribute(binding, 'srvb:version');
  const bindingCategory =
    getNodeAttribute(binding, 'srvb:category') ||
    findAttribute(binding, 'srvb:category');

  // Keep publication state unchanged by default during restore updates.
  const desiredPublicationState: IServiceBindingConfig['desiredPublicationState'] =
    'unchanged';

  const normalizedBindingType = bindingType?.toUpperCase();
  const normalizedBindingVersion = bindingVersion?.toUpperCase();
  const serviceType =
    normalizedBindingType === 'ODATA'
      ? normalizedBindingVersion === 'V2'
        ? 'odatav2'
        : 'odatav4'
      : undefined;

  return {
    bindingName,
    packageName,
    description,
    serviceDefinitionName,
    serviceName,
    serviceVersion,
    bindingType: normalizedBindingType as IServiceBindingConfig['bindingType'],
    bindingVersion,
    bindingCategory,
    masterLanguage,
    masterSystem,
    responsible,
    desiredPublicationState,
    serviceType,
  };
}
