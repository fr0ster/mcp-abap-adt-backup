#!/usr/bin/env node

/**
 * ADT Backup/Restore CLI
 *
 * Creates editable YAML backups of ABAP objects and restores them via AdtClient.
 */

import * as fs from 'node:fs';
import type {
  IBehaviorDefinitionConfig,
  IBehaviorImplementationConfig,
  IClassConfig,
  IDataElementConfig,
  IDomainConfig,
  IFunctionGroupConfig,
  IFunctionModuleConfig,
  IInterfaceConfig,
  IMetadataExtensionConfig,
  IPackageConfig,
  IProgramConfig,
  IServiceDefinitionConfig,
  IStructureConfig,
  ITableConfig,
  IViewConfig,
} from '@mcp-abap-adt/adt-clients';
import { AdtClient } from '@mcp-abap-adt/adt-clients';
import { AuthBroker } from '@mcp-abap-adt/auth-broker';
import {
  AuthorizationCodeProvider,
  ClientCredentialsProvider,
} from '@mcp-abap-adt/auth-providers';
import {
  AbapServiceKeyStore,
  AbapSessionStore,
  EnvFileSessionStore,
  resolveSearchPaths,
} from '@mcp-abap-adt/auth-stores';
import { createAbapConnection, type SapConfig } from '@mcp-abap-adt/connection';
import type {
  IAdtResponse,
  IAuthorizationConfig,
  ITokenProvider,
  ITokenRefresher,
  ITokenResult,
} from '@mcp-abap-adt/interfaces';
import { XMLParser } from 'fast-xml-parser';
import YAML from 'yaml';

type SupportedType =
  | 'package'
  | 'domain'
  | 'dataElement'
  | 'structure'
  | 'table'
  | 'tableType'
  | 'view'
  | 'class'
  | 'interface'
  | 'program'
  | 'functionGroup'
  | 'functionModule'
  | 'serviceDefinition'
  | 'metadataExtension'
  | 'behaviorDefinition'
  | 'behaviorImplementation'
  | 'enhancement'
  | 'unitTest'
  | 'cdsUnitTest';

type RestoreMode = 'create' | 'update' | 'upsert';

type BackupConfig = Record<string, unknown>;

interface ObjectSpec {
  type: SupportedType;
  name: string;
  functionGroupName?: string;
}

interface BackupObject {
  id: string;
  type: SupportedType;
  name: string;
  functionGroupName?: string;
  config: BackupConfig;
  source?: string;
  dependsOn?: string[];
}

interface BackupFile {
  schemaVersion: 1;
  generatedAt: string;
  objects: BackupObject[];
}

interface BackupTreeNode {
  name: string;
  adtType?: string;
  type?: SupportedType;
  description?: string;
  codeBase64?: string;
  codeFormat?: 'source' | 'xml' | 'json';
  restoreStatus?: 'ok' | 'not-implemented';
  config?: BackupConfig;
  functionGroupName?: string;
  children?: BackupTreeNode[];
}

interface BackupTreeFile {
  schemaVersion: 2;
  generatedAt: string;
  package: string;
  root: BackupTreeNode;
}

function usage(): string {
  return [
    'ADT Backup/Restore',
    '',
    'Commands:',
    '  backup  --objects <type:name[,type:name]> [--output file] [--destination name] [--env file] [--auth-root path]',
    '  backup  --package <name> [--output file] [--destination name] [--env file] [--auth-root path]',
    '  tree    --package <name> [--output file] [--destination name] [--env file] [--auth-root path]',
    '  restore --input <file> [--mode create|update|upsert] [--activate] [--destination name] [--env file] [--auth-root path]',
    '  extract --input <file> --object <type:name> --out <file>',
    '  patch   --input <file> --object <type:name> --file <file> [--output file]',
    '  list    --input <file> [--format text|json]',
    '  -vv/-vvv for verbose logging',
    '',
    'Examples:',
    '  adt-backup backup --objects class:ZCL_TEST,view:ZV_TEST --output backup.yaml --destination TRIAL',
    '  adt-backup backup --package ZPKG_TEST --output backup.yaml --destination TRIAL',
    '  adt-backup tree --package ZPKG_TEST --output tree.yaml --destination TRIAL',
    '  adt-backup restore --input backup.yaml --mode upsert --activate --destination TRIAL',
    '  adt-backup extract --input backup.yaml --object class:ZCL_TEST --out ZCL_TEST.abap',
    '  adt-backup patch --input backup.yaml --object class:ZCL_TEST --file ZCL_TEST.abap',
    '  adt-backup list --input backup.yaml',
    '',
    'Object type examples:',
    '  class:ZCL_TEST',
    '  interface:ZIF_TEST',
    '  program:ZREP_TEST',
    '  view:ZV_TEST',
    '  domain:ZDOM_TEST',
    '  dataElement:ZDE_TEST',
    '  structure:ZST_TEST',
    '  table:ZT_TEST',
    '  tableType:ZTT_TEST',
    '  functionGroup:ZFG_TEST',
    '  functionModule:ZFG_TEST|ZFM_TEST',
    '  serviceDefinition:Z_I_SRV_DEF',
    '  metadataExtension:Z_I_SRV_EXT',
    '  behaviorDefinition:Z_I_BDEF',
  ].join('\n');
}

function parseArgs(argv: string[]): Record<string, string | boolean> {
  const args: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith('--')) {
      continue;
    }
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith('--')) {
      args[key] = true;
    } else {
      args[key] = next;
      i += 1;
    }
  }
  return args;
}

let verbosityLevel = 0;

function applyLogEnv(level: number): void {
  if (level >= 3) {
    process.env.LOG_LEVEL = 'debug';
    process.env.DEBUG_BROKER = 'true';
    process.env.DEBUG_AUTH_BROKER = 'true';
    process.env.DEBUG_PROVIDER = 'true';
    process.env.DEBUG_AUTH_PROVIDERS = 'true';
    process.env.DEBUG_STORES = 'true';
    process.env.DEBUG_AUTH_STORES = 'true';
    process.env.DEBUG_ADT_LIBS = 'true';
    process.env.DEBUG_CONNECTORS = 'true';
    return;
  }
  if (level >= 2) {
    process.env.LOG_LEVEL = 'info';
    process.env.DEBUG_BROKER = 'true';
    process.env.DEBUG_AUTH_BROKER = 'true';
    process.env.DEBUG_PROVIDER = 'false';
    process.env.DEBUG_AUTH_PROVIDERS = 'false';
    process.env.DEBUG_STORES = 'false';
    process.env.DEBUG_AUTH_STORES = 'false';
    process.env.DEBUG_CONNECTORS = 'false';
    process.env.DEBUG_ADT_LIBS = 'true';
    return;
  }
  if (level >= 1) {
    process.env.LOG_LEVEL = 'info';
    process.env.DEBUG_BROKER = 'false';
    process.env.DEBUG_AUTH_BROKER = 'false';
    process.env.DEBUG_PROVIDER = 'false';
    process.env.DEBUG_AUTH_PROVIDERS = 'false';
    process.env.DEBUG_STORES = 'false';
    process.env.DEBUG_AUTH_STORES = 'false';
    process.env.DEBUG_CONNECTORS = 'false';
    process.env.DEBUG_ADT_LIBS = 'true';
    return;
  }
  process.env.LOG_LEVEL = 'error';
  process.env.DEBUG_BROKER = 'false';
  process.env.DEBUG_AUTH_BROKER = 'false';
  process.env.DEBUG_PROVIDER = 'false';
  process.env.DEBUG_AUTH_PROVIDERS = 'false';
  process.env.DEBUG_STORES = 'false';
  process.env.DEBUG_AUTH_STORES = 'false';
  process.env.DEBUG_CONNECTORS = 'false';
  process.env.DEBUG_ADT_LIBS = 'false';
}

function createLogger(level: number) {
  return {
    debug: (message: string, meta?: unknown) => {
      if (level >= 3) {
        console.log(message, meta ?? '');
      }
    },
    info: (message: string, meta?: unknown) => {
      if (level >= 1) {
        console.log(message, meta ?? '');
      }
    },
    warn: (message: string, meta?: unknown) => {
      if (level >= 1) {
        console.warn(message, meta ?? '');
      }
    },
    error: (message: string, meta?: unknown) => {
      console.error(message, meta ?? '');
    },
  };
}

function getVerbosity(argv: string[]): number {
  let level = 0;
  for (const arg of argv) {
    if (arg === '-v') {
      level = Math.max(level, 1);
    }
    if (arg === '-vv') {
      level = Math.max(level, 2);
    }
    if (arg === '-vvv') {
      level = Math.max(level, 3);
    }
    if (arg.startsWith('--verbose=')) {
      const value = Number(arg.split('=')[1]);
      if (!Number.isNaN(value)) {
        level = Math.max(level, value);
      }
    }
    if (arg === '--verbose') {
      level = Math.max(level, 2);
    }
  }
  return level;
}

function logVerbose(level: number, message: string): void {
  if (verbosityLevel >= level) {
    console.log(message);
  }
}

function isEnvEnabled(value: string | undefined): boolean {
  if (!value) {
    return false;
  }
  const normalized = value.trim().toLowerCase();
  return normalized === 'true' || normalized === '1' || normalized === 'yes';
}

function shouldEnableBrokerLogger(): boolean {
  return (
    isEnvEnabled(process.env.DEBUG_BROKER) ||
    isEnvEnabled(process.env.DEBUG_AUTH_BROKER) ||
    isEnvEnabled(process.env.DEBUG_AUTH_LOG)
  );
}

function shouldEnableProviderLogger(): boolean {
  return (
    isEnvEnabled(process.env.DEBUG_PROVIDER) ||
    isEnvEnabled(process.env.DEBUG_AUTH_PROVIDERS) ||
    isEnvEnabled(process.env.DEBUG_AUTH_LOG)
  );
}

function shouldEnableStoreLogger(): boolean {
  return (
    isEnvEnabled(process.env.DEBUG_STORES) ||
    isEnvEnabled(process.env.DEBUG_AUTH_STORES) ||
    isEnvEnabled(process.env.DEBUG_AUTH_LOG)
  );
}

function shouldEnableConnectionLogger(): boolean {
  return isEnvEnabled(process.env.DEBUG_CONNECTORS);
}

function shouldEnableAdtLogger(): boolean {
  return (
    isEnvEnabled(process.env.DEBUG_ADT_LIBS) ||
    isEnvEnabled(process.env.DEBUG_ADT_TESTS) ||
    isEnvEnabled(process.env.DEBUG_ADT_E2E_TESTS) ||
    isEnvEnabled(process.env.DEBUG_ADT_HELPER_TESTS)
  );
}

function normalizeType(rawType: string): SupportedType {
  const normalized = rawType.trim().toLowerCase();
  const map: Record<string, SupportedType> = {
    package: 'package',
    domain: 'domain',
    dataelement: 'dataElement',
    'data-element': 'dataElement',
    data_element: 'dataElement',
    structure: 'structure',
    table: 'table',
    tabletype: 'tableType',
    table_type: 'tableType',
    view: 'view',
    class: 'class',
    interface: 'interface',
    program: 'program',
    functiongroup: 'functionGroup',
    function_group: 'functionGroup',
    functionmodule: 'functionModule',
    function_module: 'functionModule',
    servicedefinition: 'serviceDefinition',
    service_definition: 'serviceDefinition',
    metadataextension: 'metadataExtension',
    metadata_extension: 'metadataExtension',
    behaviordefinition: 'behaviorDefinition',
    behavior_definition: 'behaviorDefinition',
    behaviorimplementation: 'behaviorImplementation',
    behavior_implementation: 'behaviorImplementation',
    enhancement: 'enhancement',
    unittest: 'unitTest',
    cdsunittest: 'cdsUnitTest',
  };

  const resolved = map[normalized];
  if (!resolved) {
    throw new Error(`Unsupported object type: ${rawType}`);
  }
  return resolved;
}

function parseObjectSpec(spec: string): ObjectSpec {
  const parts = spec.split(':');
  if (parts.length < 2) {
    throw new Error(`Invalid object spec: ${spec}`);
  }
  const type = normalizeType(parts[0]);
  const namePart = parts.slice(1).join(':').trim();
  if (!namePart) {
    throw new Error(`Missing name in object spec: ${spec}`);
  }

  if (type === 'functionModule') {
    const split = namePart.split(/[|/]/);
    if (split.length !== 2) {
      throw new Error(
        `Function module spec must be GROUP|NAME or GROUP/NAME: ${spec}`,
      );
    }
    return {
      type,
      functionGroupName: split[0].trim(),
      name: split[1].trim(),
    };
  }

  return { type, name: namePart };
}

function objectId(spec: ObjectSpec): string {
  if (spec.type === 'functionModule') {
    return `${spec.type}:${spec.functionGroupName}|${spec.name}`;
  }
  return `${spec.type}:${spec.name}`;
}

function formatObjectSpec(spec: ObjectSpec): string {
  if (spec.type === 'functionModule') {
    return `${spec.type}:${spec.functionGroupName}|${spec.name}`;
  }
  return `${spec.type}:${spec.name}`;
}

function getNodeFunctionGroupName(node: BackupTreeNode): string | undefined {
  if (node.type !== 'functionModule') {
    return undefined;
  }
  const configGroup =
    node.config && typeof node.config['functionGroupName'] === 'string'
      ? (node.config['functionGroupName'] as string)
      : undefined;
  return configGroup || node.functionGroupName;
}

function collectTreeObjects(node: BackupTreeNode, out: ObjectSpec[]): void {
  if (node.type) {
    out.push({
      type: node.type,
      name: node.name,
      functionGroupName: getNodeFunctionGroupName(node),
    });
  }
  if (node.children && node.children.length > 0) {
    for (const child of node.children) {
      collectTreeObjects(child, out);
    }
  }
}

class NoopTokenProvider implements ITokenProvider {
  async getTokens(): Promise<ITokenResult> {
    throw new Error(
      'Token provider is not configured. Ensure your destination has authorization settings or use an .env session with JWT.',
    );
  }
}

function asConfig<T>(config: BackupConfig): T {
  return config as T;
}

function toBackupConfig(value: unknown): BackupConfig {
  return value as BackupConfig;
}

function createTokenProvider(
  authConfig?: IAuthorizationConfig | null,
  logger?: ReturnType<typeof createLogger>,
): ITokenProvider {
  if (
    !authConfig ||
    !authConfig.uaaUrl ||
    !authConfig.uaaClientId ||
    !authConfig.uaaClientSecret
  ) {
    return new NoopTokenProvider();
  }

  return new AuthorizationCodeProvider({
    uaaUrl: authConfig.uaaUrl,
    clientId: authConfig.uaaClientId,
    clientSecret: authConfig.uaaClientSecret,
    refreshToken: authConfig.refreshToken,
    browser: 'system',
    logger: shouldEnableProviderLogger() ? logger : undefined,
  });
}

async function getSapConfigFromBroker(options: {
  destination?: string;
  envPath?: string;
  authRoot?: string;
  logger: ReturnType<typeof createLogger>;
}): Promise<{ config: SapConfig; tokenRefresher?: ITokenRefresher }> {
  const { logger } = options;
  const brokerLogger = shouldEnableBrokerLogger() ? logger : undefined;
  const storeLogger = shouldEnableStoreLogger() ? logger : undefined;

  const searchPaths = resolveSearchPaths(options.authRoot);
  const primaryPath = searchPaths[0];
  if (!primaryPath) {
    throw new Error('No auth search paths resolved');
  }
  const sessionStore = options.envPath
    ? new EnvFileSessionStore(options.envPath, storeLogger)
    : new AbapSessionStore(primaryPath, storeLogger);
  const serviceKeyStore = options.envPath
    ? undefined
    : new AbapServiceKeyStore(primaryPath, storeLogger);
  const destination = options.destination || 'env';
  const authConfig =
    (await sessionStore
      .getAuthorizationConfig(destination)
      .catch(() => null)) ||
    (serviceKeyStore
      ? await serviceKeyStore
          .getAuthorizationConfig(destination)
          .catch(() => null)
      : null);
  const tokenProvider = createTokenProvider(authConfig, logger);

  const broker = new AuthBroker(
    {
      sessionStore,
      serviceKeyStore,
      tokenProvider,
    },
    'chrome',
    brokerLogger,
  );

  const connConfig = await broker.getConnectionConfig(destination);
  if (!connConfig?.serviceUrl) {
    throw new Error(`Missing connection config for destination ${destination}`);
  }
  const resolvedAuthType =
    connConfig.authType ||
    (connConfig.username || connConfig.password ? 'basic' : undefined) ||
    'jwt';

  const config: SapConfig = {
    url: connConfig.serviceUrl,
    authType: resolvedAuthType,
    client: connConfig.sapClient,
  };

  if (resolvedAuthType === 'jwt') {
    const token = await broker.getToken(destination);
    if (!token) {
      throw new Error(`Missing JWT token for destination ${destination}`);
    }
    config.jwtToken = token;
  } else {
    if (!connConfig.username || !connConfig.password) {
      throw new Error(
        `Missing username/password for destination ${destination}`,
      );
    }
    config.username = connConfig.username;
    config.password = connConfig.password;
  }

  const tokenRefresher =
    resolvedAuthType === 'jwt'
      ? broker.createTokenRefresher(destination)
      : undefined;

  return { config, tokenRefresher };
}

type NodeValue = Record<string, unknown> | unknown[] | string | number | null;
type NodeRecord = Record<string, NodeValue>;

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
});

function findAttribute(
  node: NodeValue | undefined,
  attributeName: string,
): string | undefined {
  if (!node || typeof node !== 'object') {
    return undefined;
  }
  const attrKey = `@_${attributeName}`;
  if (
    !Array.isArray(node) &&
    typeof (node as NodeRecord)[attrKey] === 'string'
  ) {
    return (node as NodeRecord)[attrKey] as string;
  }
  if (Array.isArray(node)) {
    for (const value of node) {
      const found = findAttribute(value as NodeValue, attributeName);
      if (found) {
        return found;
      }
    }
    return undefined;
  }
  for (const value of Object.values(node as NodeRecord)) {
    const found = findAttribute(value, attributeName);
    if (found) {
      return found;
    }
  }
  return undefined;
}

function findPackageName(node: NodeValue): string | undefined {
  if (!node || typeof node !== 'object') {
    return undefined;
  }
  if (!Array.isArray(node) && (node as NodeRecord)['adtcore:packageRef']) {
    const ref = (node as NodeRecord)['adtcore:packageRef'];
    if (ref && typeof ref === 'object' && !Array.isArray(ref)) {
      const name =
        (ref as NodeRecord)['@_adtcore:name'] || (ref as NodeRecord)['@_name'];
      if (typeof name === 'string') {
        return name;
      }
    }
  }
  if (Array.isArray(node)) {
    for (const value of node) {
      const found = findPackageName(value as NodeValue);
      if (found) {
        return found;
      }
    }
    return undefined;
  }
  for (const value of Object.values(node as NodeRecord)) {
    const found = findPackageName(value);
    if (found) {
      return found;
    }
  }
  return undefined;
}

function extractMetadata(xml: string): {
  description?: string;
  packageName?: string;
} {
  const parsed = xmlParser.parse(xml) as NodeValue;
  const description =
    findAttribute(parsed, 'adtcore:description') ||
    findAttribute(parsed, 'description');
  const packageName = findPackageName(parsed);
  return { description, packageName };
}

function getNodeAttribute(
  node: NodeValue | undefined,
  attributeName: string,
): string | undefined {
  if (!node || typeof node !== 'object' || Array.isArray(node)) {
    return undefined;
  }
  const attrKey = `@_${attributeName}`;
  const value = (node as NodeRecord)[attrKey];
  return typeof value === 'string' ? value : undefined;
}

function findNode(
  node: NodeValue | undefined,
  keys: string[],
): NodeValue | undefined {
  if (!node || typeof node !== 'object') {
    return undefined;
  }
  if (Array.isArray(node)) {
    for (const value of node) {
      const found = findNode(value as NodeValue, keys);
      if (found !== undefined) {
        return found;
      }
    }
    return undefined;
  }
  const record = node as NodeRecord;
  for (const key of keys) {
    if (record[key] !== undefined) {
      return record[key];
    }
  }
  for (const value of Object.values(record)) {
    const found = findNode(value, keys);
    if (found !== undefined) {
      return found;
    }
  }
  return undefined;
}

function findNodeValue(
  node: NodeValue | undefined,
  keys: string[],
): string | undefined {
  const found = findNode(node, keys);
  if (typeof found === 'string' || typeof found === 'number') {
    return String(found);
  }
  return undefined;
}

function toNumber(value?: string): number | undefined {
  if (!value) {
    return undefined;
  }
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? undefined : parsed;
}

function toBoolean(value?: string): boolean | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (value === 'true' || value === 'false') {
    return value === 'true';
  }
  if (value === '1' || value === '0') {
    return value === '1';
  }
  return undefined;
}

function parsePackageConfig(xml: string): Partial<IPackageConfig> {
  const parsed = xmlParser.parse(xml) as NodeValue;
  const root = findNode(parsed, ['pak:package', 'package']) ?? parsed;
  const packageName =
    getNodeAttribute(root, 'adtcore:name') ||
    findAttribute(root, 'adtcore:name');
  const description =
    getNodeAttribute(root, 'adtcore:description') ||
    findAttribute(root, 'adtcore:description');
  const superPackageNode = findNode(root, ['pak:superPackage', 'superPackage']);
  const softwareComponentNode = findNode(root, [
    'pak:softwareComponent',
    'softwareComponent',
  ]);
  const superPackage =
    getNodeAttribute(superPackageNode, 'adtcore:name') ||
    findAttribute(superPackageNode, 'adtcore:name');
  const softwareComponent =
    getNodeAttribute(softwareComponentNode, 'pak:name') ||
    getNodeAttribute(softwareComponentNode, 'name') ||
    findAttribute(softwareComponentNode, 'pak:name') ||
    findAttribute(softwareComponentNode, 'name');
  const packageType = findNodeValue(root, ['pak:packageType', 'packageType']);
  const transportLayer = findNodeValue(root, [
    'pak:transportLayer',
    'transportLayer',
  ]);
  const applicationComponent = findNodeValue(root, [
    'pak:applicationComponent',
    'applicationComponent',
  ]);
  const responsible =
    getNodeAttribute(root, 'adtcore:responsible') ||
    findAttribute(root, 'adtcore:responsible');

  return {
    packageName,
    description,
    superPackage,
    softwareComponent,
    packageType,
    transportLayer,
    applicationComponent,
    responsible,
  };
}

function parseDomainConfig(xml: string): Partial<IDomainConfig> {
  const parsed = xmlParser.parse(xml) as NodeValue;
  const root = findNode(parsed, ['doma:domain', 'domain']) ?? parsed;
  const domainName =
    getNodeAttribute(root, 'adtcore:name') ||
    findAttribute(root, 'adtcore:name');
  const description =
    getNodeAttribute(root, 'adtcore:description') ||
    findAttribute(root, 'adtcore:description');
  const packageRef = findNode(root, ['adtcore:packageRef', 'packageRef']);
  const packageName =
    getNodeAttribute(packageRef, 'adtcore:name') ||
    findAttribute(packageRef, 'adtcore:name');

  const datatype = findNodeValue(root, ['doma:datatype', 'datatype']);
  const length = toNumber(findNodeValue(root, ['doma:length', 'length']));
  const decimals = toNumber(findNodeValue(root, ['doma:decimals', 'decimals']));
  const conversion_exit = findNodeValue(root, [
    'doma:conversionExit',
    'conversionExit',
  ]);
  const sign_exists = toBoolean(
    findNodeValue(root, ['doma:signExists', 'signExists']),
  );
  const lowercase = toBoolean(
    findNodeValue(root, ['doma:lowercase', 'lowercase']),
  );
  const valueTableRef = findNode(root, ['doma:valueTableRef', 'valueTableRef']);
  const value_table =
    getNodeAttribute(valueTableRef, 'adtcore:name') ||
    findAttribute(valueTableRef, 'adtcore:name');

  const fixedValuesNode = findNode(root, ['doma:fixValues', 'fixValues']);
  const fixed_values: Array<{ low: string; text: string }> = [];
  if (fixedValuesNode) {
    const fixValueEntries = findNode(fixedValuesNode, [
      'doma:fixValue',
      'fixValue',
    ]);
    const entries: NodeValue[] = Array.isArray(fixValueEntries)
      ? (fixValueEntries as NodeValue[])
      : fixValueEntries
        ? [fixValueEntries as NodeValue]
        : [];
    for (const entry of entries) {
      const low = findNodeValue(entry, ['doma:low', 'low']);
      const text = findNodeValue(entry, ['doma:text', 'text']);
      if (low && text) {
        fixed_values.push({ low, text });
      }
    }
  }

  return {
    domainName,
    description,
    packageName,
    datatype,
    length,
    decimals,
    conversion_exit,
    sign_exists,
    lowercase,
    value_table,
    fixed_values: fixed_values.length > 0 ? fixed_values : undefined,
  };
}

function parseDataElementConfig(xml: string): Partial<IDataElementConfig> {
  const parsed = xmlParser.parse(xml) as NodeValue;
  const root = findNode(parsed, ['blue:wbobj', 'wbobj']) ?? parsed;
  const dataElementName =
    getNodeAttribute(root, 'adtcore:name') ||
    findAttribute(root, 'adtcore:name');
  const description =
    getNodeAttribute(root, 'adtcore:description') ||
    findAttribute(root, 'adtcore:description');
  const packageRef = findNode(root, ['adtcore:packageRef', 'packageRef']);
  const packageName =
    getNodeAttribute(packageRef, 'adtcore:name') ||
    findAttribute(packageRef, 'adtcore:name');

  const typeKind = findNodeValue(root, ['dtel:typeKind', 'typeKind']) as
    | IDataElementConfig['typeKind']
    | undefined;
  const typeName = findNodeValue(root, ['dtel:typeName', 'typeName']);
  const dataType = findNodeValue(root, ['dtel:dataType', 'dataType']);
  const length = toNumber(
    findNodeValue(root, ['dtel:dataTypeLength', 'dataTypeLength']),
  );
  const decimals = toNumber(
    findNodeValue(root, ['dtel:dataTypeDecimals', 'dataTypeDecimals']),
  );
  const shortLabel = findNodeValue(root, [
    'dtel:shortFieldLabel',
    'shortFieldLabel',
  ]);
  const mediumLabel = findNodeValue(root, [
    'dtel:mediumFieldLabel',
    'mediumFieldLabel',
  ]);
  const longLabel = findNodeValue(root, [
    'dtel:longFieldLabel',
    'longFieldLabel',
  ]);
  const headingLabel = findNodeValue(root, [
    'dtel:headingFieldLabel',
    'headingFieldLabel',
  ]);
  const searchHelp = findNodeValue(root, ['dtel:searchHelp', 'searchHelp']);
  const searchHelpParameter = findNodeValue(root, [
    'dtel:searchHelpParameter',
    'searchHelpParameter',
  ]);
  const setGetParameter = findNodeValue(root, [
    'dtel:setGetParameter',
    'setGetParameter',
  ]);

  return {
    dataElementName,
    description,
    packageName,
    dataType: dataType || undefined,
    length,
    decimals,
    shortLabel,
    mediumLabel,
    longLabel,
    headingLabel,
    typeKind,
    typeName: typeName || undefined,
    searchHelp,
    searchHelpParameter,
    setGetParameter,
  };
}

function getAttribute(node: NodeRecord, keys: string[]): string | undefined {
  for (const key of keys) {
    const value = node[key];
    if (typeof value === 'string') {
      return value;
    }
  }
  return undefined;
}

function getNodeName(node: NodeRecord): string | undefined {
  return getAttribute(node, [
    '@_adtcore:name',
    '@_name',
    'adtcore:name',
    'name',
  ]);
}

function getNodeType(node: NodeRecord): string | undefined {
  return getAttribute(node, [
    '@_adtcore:type',
    '@_type',
    'adtcore:type',
    'type',
  ]);
}

function getNodeDescription(node: NodeRecord): string | undefined {
  return getAttribute(node, [
    '@_adtcore:description',
    '@_description',
    '@_shortDescription',
    'adtcore:description',
    'description',
    'shortDescription',
  ]);
}

function isNodeObject(node: NodeValue): node is NodeRecord {
  if (!node || typeof node !== 'object' || Array.isArray(node)) {
    return false;
  }
  const record = node as NodeRecord;
  return Boolean(getNodeName(record) && getNodeType(record));
}

function collectNodeObjects(value: NodeValue): NodeRecord[] {
  if (!value) {
    return [];
  }
  if (Array.isArray(value)) {
    return value.flatMap((item) => collectNodeObjects(item as NodeValue));
  }
  if (typeof value !== 'object') {
    return [];
  }
  if (isNodeObject(value)) {
    return [value];
  }
  return Object.values(value as NodeRecord).flatMap((item) =>
    collectNodeObjects(item),
  );
}

function collectChildNodes(node: NodeRecord): NodeRecord[] {
  const children: NodeRecord[] = [];
  for (const [key, value] of Object.entries(node)) {
    if (key.startsWith('@_')) {
      continue;
    }
    if (/node|child/i.test(key)) {
      children.push(...collectNodeObjects(value));
      continue;
    }
    if (typeof value === 'object' && value) {
      children.push(...collectNodeObjects(value));
    }
  }
  return children;
}

function findNodeByName(
  value: NodeValue,
  name: string,
): NodeRecord | undefined {
  if (!value) {
    return undefined;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = findNodeByName(item as NodeValue, name);
      if (found) {
        return found;
      }
    }
    return undefined;
  }
  if (typeof value !== 'object') {
    return undefined;
  }
  if (isNodeObject(value) && getNodeName(value)?.toUpperCase() === name) {
    return value;
  }
  for (const item of Object.values(value as NodeRecord)) {
    const found = findNodeByName(item, name);
    if (found) {
      return found;
    }
  }
  return undefined;
}

function parseNodeTree(
  node: NodeRecord,
  visited: Set<NodeRecord> = new Set(),
): BackupTreeNode {
  if (visited.has(node)) {
    return {
      name: getNodeName(node) || '',
      adtType: getNodeType(node),
      description: getNodeDescription(node),
      restoreStatus: 'not-implemented',
      children: [],
    };
  }
  visited.add(node);

  const children = collectChildNodes(node)
    .filter((child) => isNodeObject(child))
    .map((child) => parseNodeTree(child, visited));

  return {
    name: getNodeName(node) || '',
    adtType: getNodeType(node),
    description: getNodeDescription(node),
    restoreStatus: 'not-implemented',
    children,
  };
}

interface VirtualFolderEntry {
  name?: string;
  displayName?: string;
  facet?: string;
  text?: string;
  type?: string;
}

interface VirtualObjectEntry {
  name?: string;
  type?: string;
  text?: string;
}

function mapAdtTypeToSupported(adtType?: string): SupportedType | undefined {
  if (!adtType) {
    return undefined;
  }
  const type = adtType.toUpperCase();
  const map: Record<string, SupportedType> = {
    'DEVC/K': 'package',
    'DOMA/DD': 'domain',
    'DTEL/DE': 'dataElement',
    'TABL/DS': 'structure',
    'STRU/DT': 'structure',
    'TABL/DT': 'table',
    'TTYP/DF': 'tableType',
    'TTYP/TT': 'tableType',
    'DDLS/DF': 'view',
    'DDLX/EX': 'metadataExtension',
    'CLAS/OC': 'class',
    'INTF/IF': 'interface',
    'INTF/OI': 'interface',
    'PROG/P': 'program',
    'FUGR/FF': 'functionModule',
    'FUGR/F': 'functionGroup',
    FUGR: 'functionGroup',
    'SRVD/SRV': 'serviceDefinition',
    'BDEF/BDO': 'behaviorDefinition',
    'BIMP/BIM': 'behaviorImplementation',
    'BIMP/BI': 'behaviorImplementation',
    'BIMP/BO': 'behaviorImplementation',
  };
  if (map[type]) {
    return map[type];
  }
  if (type.startsWith('CLAS/')) return 'class';
  if (type.startsWith('INTF/')) return 'interface';
  if (type.startsWith('PROG/')) return 'program';
  if (type.startsWith('DDLS/')) return 'view';
  if (type.startsWith('DDLX/')) return 'metadataExtension';
  if (type.startsWith('SRVD/')) return 'serviceDefinition';
  if (type.startsWith('DOMA/')) return 'domain';
  if (type.startsWith('DTEL/')) return 'dataElement';
  if (type.startsWith('TABL/DS') || type.startsWith('STRU/'))
    return 'structure';
  if (type.startsWith('TABL/DT')) return 'table';
  if (type.startsWith('TTYP/')) return 'tableType';
  if (type.startsWith('FUGR/FF')) return 'functionModule';
  if (type.startsWith('FUGR/')) return 'functionGroup';
  if (type.startsWith('DEVC/')) return 'package';
  if (type.startsWith('BDEF/')) return 'behaviorDefinition';
  if (type.startsWith('BIMP/')) return 'behaviorImplementation';
  if (type.startsWith('BIMPL/')) return 'behaviorImplementation';
  return undefined;
}

function isRestoreImplemented(type?: SupportedType): boolean {
  if (!type) {
    return false;
  }
  const supported = new Set<SupportedType>([
    'package',
    'domain',
    'dataElement',
    'structure',
    'table',
    'view',
    'class',
    'interface',
    'program',
    'functionGroup',
    'functionModule',
    'serviceDefinition',
    'metadataExtension',
    'behaviorDefinition',
    'behaviorImplementation',
  ]);
  return supported.has(type);
}

function asArray<T>(value?: T | T[]): T[] {
  if (!value) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
}

function readAttr(node: NodeRecord, name: string): string | undefined {
  const value = node[`@_${name}`];
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  return undefined;
}

function parseBehaviorDefinitionFromClass(source?: string): string | undefined {
  if (!source) {
    return undefined;
  }
  const match = source.match(/FOR\s+BEHAVIOR\s+OF\s+([A-Z0-9_/]+)/i);
  return match ? match[1] : undefined;
}

function findVirtualFoldersResult(value: NodeValue): NodeRecord | undefined {
  if (!value || typeof value !== 'object') {
    return undefined;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = findVirtualFoldersResult(item as NodeValue);
      if (found) {
        return found;
      }
    }
    return undefined;
  }
  const record = value as NodeRecord;
  for (const [key, entry] of Object.entries(record)) {
    if (
      key === 'virtualFoldersResult' ||
      key.endsWith(':virtualFoldersResult')
    ) {
      return entry as NodeRecord;
    }
  }
  for (const entry of Object.values(record)) {
    const found = findVirtualFoldersResult(entry);
    if (found) {
      return found;
    }
  }
  return undefined;
}

function parseVirtualFoldersXml(xml: string): {
  folders: VirtualFolderEntry[];
  objects: VirtualObjectEntry[];
} {
  const parsed = xmlParser.parse(xml) as NodeRecord;
  const root = findVirtualFoldersResult(parsed);
  if (!root) {
    throw new Error('Failed to parse virtual folders result');
  }
  const folderNodes = asArray(
    (root['vfs:virtualFolder'] as NodeRecord | NodeRecord[] | undefined) ||
      (root['virtualFolder'] as NodeRecord | NodeRecord[] | undefined),
  );
  const objectNodes = asArray(
    (root['vfs:object'] as NodeRecord | NodeRecord[] | undefined) ||
      (root['object'] as NodeRecord | NodeRecord[] | undefined),
  );

  return {
    folders: folderNodes.map((node) => ({
      name: readAttr(node, 'name'),
      displayName: readAttr(node, 'displayName'),
      facet: readAttr(node, 'facet'),
      text: readAttr(node, 'text'),
      type: readAttr(node, 'type'),
    })),
    objects: objectNodes.map((node) => ({
      name: readAttr(node, 'name'),
      type: readAttr(node, 'type'),
      text: readAttr(node, 'text'),
    })),
  };
}

async function fetchVirtualFolders(
  client: AdtClient,
  params: {
    objectSearchPattern?: string;
    preselection?: { facet: string; values: string[] }[];
    facetOrder?: string[];
    withVersions?: boolean;
    ignoreShortDescriptions?: boolean;
  },
): Promise<{ folders: VirtualFolderEntry[]; objects: VirtualObjectEntry[] }> {
  const response = await client.getUtils().getVirtualFoldersContents(params);
  const xml =
    typeof response.data === 'string'
      ? response.data
      : JSON.stringify(response.data);
  return parseVirtualFoldersXml(xml);
}

function applyConfigName(
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
    case 'functionGroup':
      finalConfig.functionGroupName = name;
      break;
    case 'functionModule':
      finalConfig.functionModuleName = name;
      finalConfig.functionGroupName = functionGroupName;
      break;
    case 'serviceDefinition':
      finalConfig.serviceDefinitionName = name;
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
    case 'unitTest':
      finalConfig.className = name;
      break;
    case 'cdsUnitTest':
      finalConfig.cdsName = name;
      break;
  }
  return finalConfig;
}

function ensureDescription(
  config: BackupConfig,
  fallback: string,
): BackupConfig {
  if (!config.description) {
    return { ...config, description: fallback };
  }
  return config;
}

function responseToText(response?: { data?: unknown }): string | undefined {
  if (!response) {
    return undefined;
  }
  return typeof response.data === 'string'
    ? response.data
    : JSON.stringify(response.data);
}

async function readSourceText(
  client: AdtClient,
  spec: ObjectSpec,
): Promise<string | undefined> {
  switch (spec.type) {
    case 'class': {
      const state = await client
        .getClass()
        .read({ className: spec.name }, 'active');
      return responseToText(state?.readResult);
    }
    case 'interface': {
      const state = await client
        .getInterface()
        .read({ interfaceName: spec.name }, 'active');
      return responseToText(state?.readResult);
    }
    case 'program': {
      const state = await client
        .getProgram()
        .read({ programName: spec.name }, 'active');
      return responseToText(state?.readResult);
    }
    case 'structure': {
      const state = await client
        .getStructure()
        .read({ structureName: spec.name }, 'active');
      return responseToText(state?.readResult);
    }
    case 'table': {
      const state = await client
        .getTable()
        .read({ tableName: spec.name }, 'active');
      return responseToText(state?.readResult);
    }
    case 'view': {
      const state = await client
        .getView()
        .read({ viewName: spec.name }, 'active');
      return responseToText(state?.readResult);
    }
    case 'tableType': {
      const state = await client
        .getTableType()
        .read({ tableTypeName: spec.name }, 'active');
      return responseToText(state?.readResult);
    }
    case 'functionModule': {
      if (!spec.functionGroupName) {
        return undefined;
      }
      const state = await client.getFunctionModule().read(
        {
          functionGroupName: spec.functionGroupName,
          functionModuleName: spec.name,
        },
        'active',
      );
      return responseToText(state?.readResult);
    }
    case 'serviceDefinition': {
      const state = await client
        .getServiceDefinition()
        .read({ serviceDefinitionName: spec.name }, 'active');
      return responseToText(state?.readResult);
    }
    case 'metadataExtension': {
      const state = await client
        .getMetadataExtension()
        .read({ name: spec.name }, 'active');
      return responseToText(state?.readResult);
    }
    case 'behaviorDefinition': {
      const state = await client
        .getBehaviorDefinition()
        .read({ name: spec.name }, 'active');
      return responseToText(state?.readResult);
    }
    case 'behaviorImplementation': {
      const state = await client
        .getBehaviorImplementation()
        .read({ className: spec.name }, 'active');
      return responseToText(state?.readResult);
    }
    default:
      return undefined;
  }
}

async function readBasicMetadata(
  client: AdtClient,
  spec: ObjectSpec,
): Promise<{ description?: string; packageName?: string }> {
  switch (spec.type) {
    case 'class': {
      const state = await client
        .getClass()
        .readMetadata({ className: spec.name });
      const xml = responseToText(state.metadataResult);
      return xml ? extractMetadata(xml) : {};
    }
    case 'interface': {
      const state = await client
        .getInterface()
        .readMetadata({ interfaceName: spec.name });
      const xml = responseToText(state.metadataResult);
      return xml ? extractMetadata(xml) : {};
    }
    case 'program': {
      const state = await client
        .getProgram()
        .readMetadata({ programName: spec.name });
      const xml = responseToText(state.metadataResult);
      return xml ? extractMetadata(xml) : {};
    }
    case 'structure': {
      const state = await client
        .getStructure()
        .readMetadata({ structureName: spec.name });
      const xml = responseToText(state.metadataResult);
      return xml ? extractMetadata(xml) : {};
    }
    case 'table': {
      const state = await client
        .getTable()
        .readMetadata({ tableName: spec.name });
      const xml = responseToText(state.metadataResult);
      return xml ? extractMetadata(xml) : {};
    }
    case 'tableType': {
      const state = await client
        .getTableType()
        .readMetadata({ tableTypeName: spec.name });
      const xml = responseToText(state.metadataResult);
      return xml ? extractMetadata(xml) : {};
    }
    case 'functionModule': {
      if (!spec.functionGroupName) {
        return {};
      }
      const state = await client.getFunctionModule().readMetadata({
        functionGroupName: spec.functionGroupName,
        functionModuleName: spec.name,
      });
      const xml = responseToText(state.metadataResult);
      return xml ? extractMetadata(xml) : {};
    }
    default:
      return {};
  }
}

async function backupObject(
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
    case 'behaviorImplementation': {
      const metadataXml = await readMetadataXmlForType(
        client,
        spec.type,
        spec.name,
      );
      const metadata = metadataXml ? extractMetadata(metadataXml) : {};
      const source = await readSourceText(client, spec);
      const behaviorDefinition = parseBehaviorDefinitionFromClass(source);
      const config = applyConfigName(spec.type, spec.name, undefined, {
        description: metadata.description,
        packageName: metadata.packageName,
        behaviorDefinition,
        sourceCode: source,
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

const typeOrder: SupportedType[] = [
  'package',
  'domain',
  'dataElement',
  'structure',
  'table',
  'tableType',
  'view',
  'functionGroup',
  'functionModule',
  'interface',
  'class',
  'program',
  'serviceDefinition',
  'metadataExtension',
  'behaviorDefinition',
  'behaviorImplementation',
];

function encodeBase64(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64');
}

function decodeBase64(value: string): string {
  return Buffer.from(value, 'base64').toString('utf8');
}

async function readMetadataXmlForType(
  client: AdtClient,
  type: SupportedType,
  name: string,
  functionGroupName?: string,
): Promise<string | undefined> {
  switch (type) {
    case 'class': {
      const state = await client.getClass().readMetadata({ className: name });
      return responseToText(state.metadataResult);
    }
    case 'interface': {
      const state = await client
        .getInterface()
        .readMetadata({ interfaceName: name });
      return responseToText(state.metadataResult);
    }
    case 'program': {
      const state = await client
        .getProgram()
        .readMetadata({ programName: name });
      return responseToText(state.metadataResult);
    }
    case 'structure': {
      const state = await client
        .getStructure()
        .readMetadata({ structureName: name });
      return responseToText(state.metadataResult);
    }
    case 'table': {
      const state = await client.getTable().readMetadata({ tableName: name });
      return responseToText(state.metadataResult);
    }
    case 'tableType': {
      const state = await client
        .getTableType()
        .readMetadata({ tableTypeName: name });
      return responseToText(state.metadataResult);
    }
    case 'domain': {
      const state = await client.getDomain().readMetadata({ domainName: name });
      return responseToText(state.metadataResult);
    }
    case 'dataElement': {
      const state = await client
        .getDataElement()
        .readMetadata({ dataElementName: name });
      return responseToText(state.metadataResult);
    }
    case 'functionGroup': {
      const state = await client
        .getFunctionGroup()
        .readMetadata({ functionGroupName: name });
      return responseToText(state.metadataResult);
    }
    case 'functionModule': {
      if (!functionGroupName) {
        return undefined;
      }
      const state = await client.getFunctionModule().readMetadata({
        functionGroupName,
        functionModuleName: name,
      });
      return responseToText(state.metadataResult);
    }
    case 'package': {
      const state = await client
        .getPackage()
        .readMetadata({ packageName: name });
      return responseToText(state.metadataResult);
    }
    case 'serviceDefinition': {
      const state = await client
        .getServiceDefinition()
        .readMetadata({ serviceDefinitionName: name });
      return responseToText(state.metadataResult);
    }
    case 'metadataExtension': {
      const state = await client.getMetadataExtension().readMetadata({ name });
      return responseToText(state.metadataResult);
    }
    case 'behaviorDefinition': {
      const state = await client.getBehaviorDefinition().readMetadata({ name });
      return responseToText(state.metadataResult);
    }
    case 'behaviorImplementation': {
      const state = await client
        .getBehaviorImplementation()
        .readMetadata({ className: name });
      return responseToText(state.metadataResult);
    }
    default:
      return undefined;
  }
}

async function buildConfigForNode(
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

async function readPayloadForType(
  client: AdtClient,
  type: SupportedType,
  name: string,
  functionGroupName?: string,
): Promise<{ payload?: string; format?: BackupTreeNode['codeFormat'] }> {
  switch (type) {
    case 'class':
    case 'interface':
    case 'program':
    case 'view':
    case 'structure':
    case 'table':
    case 'functionModule':
    case 'serviceDefinition':
    case 'metadataExtension':
    case 'behaviorDefinition':
    case 'behaviorImplementation':
    case 'tableType': {
      const payload = await readSourceText(client, {
        type,
        name,
        functionGroupName,
      });
      return { payload, format: 'source' };
    }
    case 'domain':
    case 'dataElement':
    case 'package':
    case 'functionGroup': {
      const xml = await readMetadataXmlForType(
        client,
        type,
        name,
        functionGroupName,
      );
      return { payload: xml, format: 'xml' };
    }
    default:
      return {};
  }
}

async function enrichTreeNode(
  node: BackupTreeNode,
  client: AdtClient,
  includeCode: boolean,
  parentFunctionGroupName?: string,
): Promise<BackupTreeNode> {
  const mappedType = mapAdtTypeToSupported(node.adtType);
  const functionGroupName =
    mappedType === 'functionGroup'
      ? node.name
      : mappedType === 'functionModule'
        ? parentFunctionGroupName
        : parentFunctionGroupName;
  const { restoreStatus: _restoreStatus, ...nodeBase } = node;
  const nextNode: BackupTreeNode = {
    ...nodeBase,
    type: mappedType,
    functionGroupName,
  };
  if (mappedType) {
    nextNode.restoreStatus = isRestoreImplemented(mappedType)
      ? 'ok'
      : 'not-implemented';
  }

  if (verbosityLevel >= 3) {
    logVerbose(
      3,
      `Node: ${node.name} [${node.adtType || 'unknown'}] -> ${mappedType || 'unknown'} (${nextNode.restoreStatus})`,
    );
  }

  const metadataXml =
    mappedType && includeCode
      ? await readMetadataXmlForType(client, mappedType, node.name)
      : undefined;

  if (!nextNode.description && metadataXml) {
    nextNode.description = extractMetadata(metadataXml).description;
  }

  if (mappedType && includeCode) {
    const config = await buildConfigForNode(
      mappedType,
      node.name,
      functionGroupName,
      metadataXml,
    );
    if (config) {
      nextNode.config = ensureDescription(config, node.name);
    }
  }

  if (mappedType && includeCode && isRestoreImplemented(mappedType)) {
    const payload = await readPayloadForType(
      client,
      mappedType,
      node.name,
      functionGroupName,
    );
    if (payload.payload) {
      nextNode.codeBase64 = encodeBase64(payload.payload);
      nextNode.codeFormat = payload.format;
      if (mappedType === 'behaviorImplementation') {
        const behaviorDefinition = parseBehaviorDefinitionFromClass(
          payload.payload,
        );
        if (behaviorDefinition) {
          nextNode.config = {
            ...(nextNode.config || {}),
            behaviorDefinition,
          };
        }
      }
    } else {
      nextNode.restoreStatus = 'not-implemented';
    }
  }

  if (node.children && node.children.length > 0) {
    const children: BackupTreeNode[] = [];
    for (const child of node.children) {
      children.push(
        await enrichTreeNode(child, client, includeCode, functionGroupName),
      );
    }
    nextNode.children = children;
  }

  return nextNode;
}

async function buildPackageBackupTreeFromVirtualFolders(
  client: AdtClient,
  packageName: string,
  includeCode: boolean,
): Promise<BackupTreeFile> {
  const packageNameUpper = packageName.toUpperCase();
  const rootTree: BackupTreeNode = {
    name: packageNameUpper,
    adtType: 'DEVC/K',
    restoreStatus: 'not-implemented',
    children: [],
  };

  logVerbose(2, `Fetching virtual folders for ${packageNameUpper}`);

  const baseSelection = [{ facet: 'PACKAGE', values: [packageNameUpper] }];
  const groupResult = await fetchVirtualFolders(client, {
    objectSearchPattern: '*',
    preselection: baseSelection,
    facetOrder: ['GROUP'],
  });
  const groups = groupResult.folders.filter(
    (entry) => entry.facet?.toUpperCase() === 'GROUP',
  );

  for (const group of groups) {
    const groupSelection = group.name || group.displayName || 'GROUP';
    const groupLabel = group.displayName || group.name || 'GROUP';
    const groupNode: BackupTreeNode = {
      name: groupLabel,
      description: groupLabel !== groupSelection ? groupSelection : undefined,
      restoreStatus: 'not-implemented',
      children: [],
    };

    const typeResult = await fetchVirtualFolders(client, {
      objectSearchPattern: '*',
      preselection: [
        ...baseSelection,
        { facet: 'GROUP', values: [groupSelection] },
      ],
      facetOrder: ['TYPE'],
    });
    const types = typeResult.folders.filter(
      (entry) => entry.facet?.toUpperCase() === 'TYPE',
    );

    for (const type of types) {
      const typeSelection = type.name || type.displayName || 'TYPE';
      const typeLabel = type.displayName || type.name || 'TYPE';
      const typeNode: BackupTreeNode = {
        name: typeLabel,
        description: typeLabel !== typeSelection ? typeSelection : undefined,
        restoreStatus: 'not-implemented',
        children: [],
      };

      const objectResult = await fetchVirtualFolders(client, {
        objectSearchPattern: '*',
        preselection: [
          ...baseSelection,
          { facet: 'GROUP', values: [groupSelection] },
          { facet: 'TYPE', values: [typeSelection] },
        ],
        facetOrder: [],
      });

      typeNode.children = objectResult.objects
        .filter((entry) => entry.name)
        .map((entry) => ({
          name: entry.name || '',
          adtType: entry.type,
          description: entry.text,
          restoreStatus: 'not-implemented',
          children: [],
        }));

      groupNode.children?.push(typeNode);
    }

    rootTree.children?.push(groupNode);
  }

  logVerbose(2, `Building node tree for ${packageNameUpper}`);
  const enrichedRoot = await enrichTreeNode(rootTree, client, includeCode);

  return {
    schemaVersion: 2,
    generatedAt: new Date().toISOString(),
    package: packageNameUpper,
    root: enrichedRoot,
  };
}

async function getPackageContents(
  client: AdtClient,
  packageName: string,
): Promise<IAdtResponse> {
  return await client.getUtils().getPackageContents(packageName);
}

async function buildPackageBackupTreeFromNodeStructure(
  client: AdtClient,
  packageName: string,
  includeCode: boolean,
): Promise<BackupTreeFile> {
  const packageNameUpper = packageName.toUpperCase();
  logVerbose(
    2,
    `Fetching package contents for ${packageNameUpper} (includeCode=${includeCode})`,
  );
  const response = await getPackageContents(client, packageNameUpper);
  const xml =
    typeof response.data === 'string'
      ? response.data
      : JSON.stringify(response.data);
  const parsed = xmlParser.parse(xml);
  const rootNodeObject =
    findNodeByName(parsed, packageNameUpper) || collectNodeObjects(parsed)[0];

  if (!rootNodeObject) {
    const fallbackPath = `/tmp/adt-backup-nodestructure-${packageNameUpper}.xml`;
    try {
      fs.writeFileSync(fallbackPath, xml, 'utf8');
    } catch (_error) {
      throw new Error(`Failed to parse package tree for ${packageNameUpper}`);
    }
    throw new Error(
      `Failed to parse package tree for ${packageNameUpper}. Raw response saved to ${fallbackPath}`,
    );
  }

  logVerbose(2, `Building node tree for ${packageNameUpper}`);
  const rootTree = parseNodeTree(rootNodeObject);
  const enrichedRoot = await enrichTreeNode(rootTree, client, includeCode);

  return {
    schemaVersion: 2,
    generatedAt: new Date().toISOString(),
    package: packageNameUpper,
    root: enrichedRoot,
  };
}

async function buildPackageBackupTree(
  client: AdtClient,
  packageName: string,
  includeCode: boolean,
): Promise<BackupTreeFile> {
  try {
    return await buildPackageBackupTreeFromVirtualFolders(
      client,
      packageName,
      includeCode,
    );
  } catch (error) {
    logVerbose(
      1,
      `Virtual folder tree failed, falling back to node structure: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
    return buildPackageBackupTreeFromNodeStructure(
      client,
      packageName,
      includeCode,
    );
  }
}

function stripCodeFromTree(node: BackupTreeNode): BackupTreeNode {
  const cleaned: BackupTreeNode = {
    name: node.name,
    adtType: node.adtType,
    type: node.type,
    description: node.description,
    functionGroupName: node.functionGroupName,
  };
  if (node.type) {
    cleaned.restoreStatus = node.restoreStatus;
  }
  if (node.children && node.children.length > 0) {
    cleaned.children = node.children.map(stripCodeFromTree);
  }
  return cleaned;
}

function findNodeInTree(
  node: BackupTreeNode,
  spec: ObjectSpec,
): BackupTreeNode | undefined {
  if (
    node.type === spec.type &&
    node.name.toUpperCase() === spec.name.toUpperCase()
  ) {
    if (spec.type !== 'functionModule') {
      return node;
    }
    const configGroup =
      node.config && typeof node.config['functionGroupName'] === 'string'
        ? node.config['functionGroupName']
        : undefined;
    const group =
      configGroup || node.functionGroupName || spec.functionGroupName;
    if (
      group &&
      spec.functionGroupName &&
      group.toUpperCase() === spec.functionGroupName.toUpperCase()
    ) {
      return node;
    }
  }
  if (!node.children) {
    return undefined;
  }
  for (const child of node.children) {
    const found = findNodeInTree(child, spec);
    if (found) {
      return found;
    }
  }
  return undefined;
}

function flattenTree(
  node: BackupTreeNode,
  result: BackupTreeNode[] = [],
): BackupTreeNode[] {
  result.push(node);
  if (node.children) {
    for (const child of node.children) {
      flattenTree(child, result);
    }
  }
  return result;
}

function sortByDependencies(objects: BackupObject[]): BackupObject[] {
  const idToObject = new Map(objects.map((obj) => [obj.id, obj]));
  const dependencies = new Map<string, Set<string>>();
  const indegree = new Map<string, number>();

  for (const obj of objects) {
    const deps = new Set(
      (obj.dependsOn || []).filter((dep) => idToObject.has(dep)),
    );
    dependencies.set(obj.id, deps);
    indegree.set(obj.id, deps.size);
  }

  const priority = new Map(typeOrder.map((type, index) => [type, index]));

  const queue = objects
    .filter((obj) => (indegree.get(obj.id) || 0) === 0)
    .sort((a, b) => {
      const aOrder = priority.get(a.type) ?? 999;
      const bOrder = priority.get(b.type) ?? 999;
      return aOrder - bOrder || a.id.localeCompare(b.id);
    })
    .map((obj) => obj.id);

  const result: BackupObject[] = [];
  const visited = new Set<string>();

  while (queue.length > 0) {
    const id = queue.shift();
    if (!id) {
      continue;
    }
    const obj = idToObject.get(id);
    if (!obj || visited.has(id)) {
      continue;
    }
    visited.add(id);
    result.push(obj);

    for (const [otherId, deps] of dependencies.entries()) {
      if (!deps.has(id)) {
        continue;
      }
      deps.delete(id);
      const nextIndegree = (indegree.get(otherId) || 0) - 1;
      indegree.set(otherId, nextIndegree);
      if (nextIndegree === 0) {
        queue.push(otherId);
        queue.sort((aId, bId) => {
          const aObj = idToObject.get(aId);
          const bObj = idToObject.get(bId);
          const aOrder = aObj ? (priority.get(aObj.type) ?? 999) : 999;
          const bOrder = bObj ? (priority.get(bObj.type) ?? 999) : 999;
          return aOrder - bOrder || aId.localeCompare(bId);
        });
      }
    }
  }

  if (result.length !== objects.length) {
    const remaining = objects.filter((obj) => !visited.has(obj.id));
    remaining.sort((a, b) => {
      const aOrder = priority.get(a.type) ?? 999;
      const bOrder = priority.get(b.type) ?? 999;
      return aOrder - bOrder || a.id.localeCompare(b.id);
    });
    result.push(...remaining);
  }

  return result;
}

async function restoreObject(
  client: AdtClient,
  obj: BackupObject,
  mode: RestoreMode,
  activate: boolean,
): Promise<void> {
  const baseConfig = applyConfigName(
    obj.type,
    obj.name,
    obj.functionGroupName,
    obj.config,
  );
  const config = ensureDescription(baseConfig, obj.name);

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
  }
}

async function restoreTreeNode(
  client: AdtClient,
  node: BackupTreeNode,
  mode: RestoreMode,
  activate: boolean,
): Promise<void> {
  if (!node.type || node.restoreStatus !== 'ok') {
    return;
  }
  const config = ensureDescription(node.config || {}, node.name);
  const payload = node.codeBase64 ? decodeBase64(node.codeBase64) : undefined;
  const options = {
    activateOnCreate: activate,
    activateOnUpdate: activate,
  };

  switch (node.type) {
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
        await client.getTable().create(asConfig<ITableConfig>(config), options);
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
        await client.getClass().create(asConfig<IClassConfig>(config), options);
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
  }
}

async function restoreTreeBackup(
  client: AdtClient,
  root: BackupTreeNode,
  mode: RestoreMode,
  activate: boolean,
): Promise<void> {
  const nodes = flattenTree(root).filter(
    (node) => node.type && node.restoreStatus === 'ok',
  );
  const priority = new Map(typeOrder.map((type, index) => [type, index]));
  nodes.sort((a, b) => {
    const aOrder = a.type ? (priority.get(a.type) ?? 999) : 999;
    const bOrder = b.type ? (priority.get(b.type) ?? 999) : 999;
    return aOrder - bOrder || a.name.localeCompare(b.name);
  });

  logVerbose(
    2,
    `Restoring ${nodes.length} node(s) from tree (mode=${mode}, activate=${activate})`,
  );
  for (const node of nodes) {
    logVerbose(3, `Restore ${node.type}:${node.name}`);
    if (mode === 'upsert') {
      try {
        await restoreTreeNode(client, node, 'create', activate);
      } catch (_error) {
        await restoreTreeNode(client, node, 'update', activate);
      }
    } else {
      await restoreTreeNode(client, node, mode, activate);
    }
  }
}

async function restoreObjects(
  client: AdtClient,
  objects: BackupObject[],
  mode: RestoreMode,
  activate: boolean,
): Promise<void> {
  const ordered = sortByDependencies(objects);
  logVerbose(
    2,
    `Restoring ${ordered.length} object(s) in flat mode (mode=${mode}, activate=${activate})`,
  );
  for (const obj of ordered) {
    logVerbose(3, `Restore ${obj.type}:${obj.name}`);
    if (mode === 'upsert') {
      try {
        await restoreObject(client, obj, 'create', activate);
      } catch (_error) {
        await restoreObject(client, obj, 'update', activate);
      }
    } else {
      await restoreObject(client, obj, mode, activate);
    }
  }
}

async function run(): Promise<void> {
  const argv = process.argv.slice(2);
  verbosityLevel = getVerbosity(argv);
  applyLogEnv(verbosityLevel);
  const logger = createLogger(verbosityLevel);
  const command = argv[0];
  const args = parseArgs(argv.slice(1));

  if (!command || command === '--help' || command === '-h') {
    console.log(usage());
    process.exit(0);
  }

  if (command === 'extract') {
    const input = args.input;
    const objectSpec = args.object;
    const output = args.out;
    if (typeof input !== 'string') {
      throw new Error('Missing --input');
    }
    if (typeof objectSpec !== 'string') {
      throw new Error('Missing --object');
    }
    if (typeof output !== 'string') {
      throw new Error('Missing --out');
    }
    logVerbose(2, `Extracting ${objectSpec} from ${input}`);
    const raw = fs.readFileSync(input, 'utf8');
    const parsed = YAML.parse(raw) as BackupTreeFile;
    if (!parsed || parsed.schemaVersion !== 2) {
      throw new Error('Extract supports only schemaVersion 2 backups');
    }
    const spec = parseObjectSpec(objectSpec);
    logVerbose(3, `Parsed object spec: ${spec.type}:${spec.name}`);
    const node = findNodeInTree(parsed.root, spec);
    if (!node || !node.codeBase64) {
      throw new Error('Object not found or no codeBase64 in backup');
    }
    fs.writeFileSync(output, decodeBase64(node.codeBase64), 'utf8');
    console.log(`Extracted to ${output}`);
    return;
  }

  if (command === 'list') {
    const input = args.input;
    if (typeof input !== 'string') {
      throw new Error('Missing --input');
    }
    const format = typeof args.format === 'string' ? args.format : 'text';
    const raw = fs.readFileSync(input, 'utf8');
    const parsed = YAML.parse(raw) as BackupFile | BackupTreeFile;
    if (!parsed || typeof parsed !== 'object') {
      throw new Error('Invalid backup file format');
    }

    if ((parsed as BackupTreeFile).schemaVersion === 2) {
      const tree = parsed as BackupTreeFile;
      const objects: ObjectSpec[] = [];
      collectTreeObjects(tree.root, objects);
      if (format === 'json') {
        console.log(JSON.stringify(objects, null, 2));
      } else {
        for (const spec of objects) {
          console.log(formatObjectSpec(spec));
        }
      }
      return;
    }

    if ((parsed as BackupFile).schemaVersion === 1) {
      const flat = parsed as BackupFile;
      const objects = flat.objects.map((obj) => ({
        type: obj.type,
        name: obj.name,
        functionGroupName: obj.functionGroupName,
      }));
      if (format === 'json') {
        console.log(JSON.stringify(objects, null, 2));
      } else {
        for (const spec of objects) {
          console.log(formatObjectSpec(spec));
        }
      }
      return;
    }

    throw new Error('Invalid backup file format');
  }

  if (command === 'patch') {
    const input = args.input;
    const objectSpec = args.object;
    const filePath = args.file;
    if (typeof input !== 'string') {
      throw new Error('Missing --input');
    }
    if (typeof objectSpec !== 'string') {
      throw new Error('Missing --object');
    }
    if (typeof filePath !== 'string') {
      throw new Error('Missing --file');
    }
    const output = typeof args.output === 'string' ? args.output : input;
    logVerbose(2, `Patching ${objectSpec} in ${input}`);
    const raw = fs.readFileSync(input, 'utf8');
    const parsed = YAML.parse(raw) as BackupTreeFile;
    if (!parsed || parsed.schemaVersion !== 2) {
      throw new Error('Patch supports only schemaVersion 2 backups');
    }
    const spec = parseObjectSpec(objectSpec);
    logVerbose(3, `Parsed object spec: ${spec.type}:${spec.name}`);
    const node = findNodeInTree(parsed.root, spec);
    if (!node) {
      throw new Error('Object not found in backup');
    }
    const fileContent = fs.readFileSync(filePath, 'utf8');
    node.codeBase64 = encodeBase64(fileContent);
    node.restoreStatus = 'ok';
    if (!node.codeFormat) {
      node.codeFormat = 'source';
    }
    const yamlText = YAML.stringify(parsed, { lineWidth: 0 });
    fs.writeFileSync(output as string, yamlText, 'utf8');
    console.log(`Backup updated at ${output}`);
    return;
  }

  const envPath =
    typeof args.env === 'string'
      ? args.env
      : typeof args.config === 'string'
        ? args.config
        : undefined;
  const destination =
    typeof args.destination === 'string' ? args.destination : undefined;
  const authRoot =
    typeof args['auth-root'] === 'string' ? args['auth-root'] : undefined;
  if (!envPath && !destination) {
    throw new Error('Missing --destination (or provide --env)');
  }
  const { config, tokenRefresher } = await getSapConfigFromBroker({
    destination,
    envPath,
    authRoot,
    logger,
  });
  const connectionLogger = shouldEnableConnectionLogger() ? logger : undefined;
  const adtLogger = shouldEnableAdtLogger() ? logger : undefined;
  const connection = createAbapConnection(
    config,
    connectionLogger,
    undefined,
    tokenRefresher,
  );
  const client = new AdtClient(connection, adtLogger);

  if (command === 'backup') {
    const rawObjects = args.objects;
    const packageName =
      typeof args.package === 'string' ? args.package : undefined;

    if (packageName) {
      logVerbose(2, `Starting package backup for ${packageName}`);
      const output =
        typeof args.output === 'string' ? args.output : 'backup.yaml';
      const tree = await buildPackageBackupTree(client, packageName, true);
      const yamlText = YAML.stringify(tree, { lineWidth: 0 });
      fs.writeFileSync(output, yamlText, 'utf8');
      console.log(`Backup written to ${output}`);
      return;
    }

    if (typeof rawObjects !== 'string') {
      throw new Error('Missing --objects or --package');
    }
    logVerbose(2, `Starting objects backup (${rawObjects})`);
    const specs = rawObjects
      .split(',')
      .map((spec) => spec.trim())
      .filter(Boolean)
      .map(parseObjectSpec);

    const objects: BackupObject[] = [];
    for (const spec of specs) {
      logVerbose(3, `Backup ${spec.type}:${spec.name}`);
      const backup = await backupObject(client, spec);
      objects.push(backup);
    }

    const output =
      typeof args.output === 'string' ? args.output : 'backup.yaml';
    const payload: BackupFile = {
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      objects,
    };
    const yamlText = YAML.stringify(payload, { lineWidth: 0 });
    fs.writeFileSync(output, yamlText, 'utf8');
    console.log(`Backup written to ${output}`);
    return;
  }

  if (command === 'tree') {
    const packageName =
      typeof args.package === 'string' ? args.package : undefined;
    if (!packageName) {
      throw new Error('Missing --package');
    }
    logVerbose(2, `Starting tree preview for ${packageName}`);
    const output = typeof args.output === 'string' ? args.output : 'tree.yaml';
    const tree = await buildPackageBackupTree(client, packageName, false);
    const lightTree: BackupTreeFile = {
      ...tree,
      root: stripCodeFromTree(tree.root),
    };
    const yamlText = YAML.stringify(lightTree, { lineWidth: 0 });
    fs.writeFileSync(output, yamlText, 'utf8');
    console.log(`Tree written to ${output}`);
    return;
  }

  if (command === 'restore') {
    const input = args.input;
    if (typeof input !== 'string') {
      throw new Error('Missing --input');
    }
    logVerbose(2, `Starting restore from ${input}`);
    const raw = fs.readFileSync(input, 'utf8');
    const mode = (args.mode as RestoreMode) || 'upsert';
    const activate = Boolean(args.activate);
    const parsed = YAML.parse(raw) as BackupFile | BackupTreeFile;
    if (!parsed || typeof parsed !== 'object') {
      throw new Error('Invalid backup file format');
    }
    if ((parsed as BackupTreeFile).schemaVersion === 2) {
      const tree = parsed as BackupTreeFile;
      logVerbose(2, `Restoring tree backup for package ${tree.package}`);
      await restoreTreeBackup(client, tree.root, mode, activate);
      console.log('Restore completed');
      return;
    }
    if (!Array.isArray((parsed as BackupFile).objects)) {
      throw new Error('Invalid backup file format');
    }
    const flat = parsed as BackupFile;
    logVerbose(2, `Restoring flat backup (${flat.objects.length} objects)`);
    await restoreObjects(client, flat.objects, mode, activate);
    console.log(`Restore completed for ${flat.objects.length} object(s)`);
    return;
  }

  throw new Error(`Unknown command: ${command}`);
}

run().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
