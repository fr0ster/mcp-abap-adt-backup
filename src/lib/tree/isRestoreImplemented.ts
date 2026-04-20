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
    case 'transformation':
    case 'serviceDefinition':
    case 'serviceBinding':
    case 'metadataExtension':
    case 'behaviorDefinition':
    case 'behaviorImplementation':
    case 'enhancement':
    case 'accessControl':
      return true;
    default:
      return false;
  }
}
