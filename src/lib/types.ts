export type SupportedType =
  | 'package'
  | 'domain'
  | 'dataElement'
  | 'structure'
  | 'table'
  | 'tableType'
  | 'ddl'
  | 'scalarFunction'
  | 'class'
  | 'interface'
  | 'program'
  | 'transformation'
  | 'functionGroup'
  | 'functionModule'
  | 'functionInclude'
  | 'serviceDefinition'
  | 'serviceBinding'
  | 'metadataExtension'
  | 'behaviorDefinition'
  | 'behaviorImplementation'
  | 'enhancement'
  | 'accessControl'
  | 'unitTest'
  | 'cdsUnitTest';

export type RestoreMode = 'create' | 'update' | 'upsert' | 'skip';

export type BackupConfig = Record<string, unknown>;

export interface ObjectSpec {
  type: SupportedType;
  name: string;
  functionGroupName?: string;
}

export interface BackupObject {
  id: string;
  type: SupportedType;
  name: string;
  functionGroupName?: string;
  config: BackupConfig;
  source?: string;
  dependsOn?: string[];
}

export interface BackupFile {
  schemaVersion: 1;
  generatedAt: string;
  objects: BackupObject[];
  checksum?: string;
}

export interface BackupTreeNode {
  name: string;
  adtType?: string;
  type?: SupportedType;
  description?: string;
  codeBase64?: string;
  codeFormat?: 'source' | 'xml' | 'json';
  codeChecksum?: string;
  usedBy?: string[];
  restoreStatus?: 'ok' | 'not-implemented';
  config?: BackupConfig;
  functionGroupName?: string;
  children?: BackupTreeNode[];
}

export interface BackupTreeFile {
  schemaVersion: 2;
  generatedAt: string;
  package: string;
  root: BackupTreeNode;
  checksum?: string;
}

export interface RestorePlanAction {
  id: string;
  type: SupportedType;
  name: string;
  functionGroupName?: string;
  action: 'create' | 'update' | 'skip';
  adtType?: string;
}

export interface RestorePlanGroup {
  id: number;
  isCircular: boolean;
  actions: RestorePlanAction[];
}

export interface RestorePlan {
  schemaVersion: 1;
  generatedAt: string;
  backupFile: string;
  targetPackage: string;
  groups: RestorePlanGroup[];
}

export type NodeValue =
  | Record<string, unknown>
  | unknown[]
  | string
  | number
  | null;
export type NodeRecord = Record<string, NodeValue>;

export interface VirtualFolderEntry {
  name?: string;
  displayName?: string;
  facet?: string;
  text?: string;
  type?: string;
}

export interface VirtualObjectEntry {
  name?: string;
  type?: string;
  text?: string;
  packageName?: string;
}
