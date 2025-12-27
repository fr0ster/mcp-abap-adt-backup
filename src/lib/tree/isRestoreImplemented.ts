import type { SupportedType } from '../types';

export function isRestoreImplemented(type?: SupportedType): boolean {
  switch (type) {
    case 'package':
    case 'domain':
    case 'dataElement':
    case 'structure':
    case 'table':
    case 'tableType':
    case 'view':
    case 'functionGroup':
    case 'functionModule':
    case 'interface':
    case 'class':
    case 'program':
    case 'serviceDefinition':
    case 'metadataExtension':
    case 'behaviorDefinition':
    case 'behaviorImplementation':
      return true;
    default:
      return false;
  }
}
