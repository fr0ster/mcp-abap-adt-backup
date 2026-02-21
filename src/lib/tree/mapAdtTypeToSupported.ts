import type { SupportedType } from '../types';

export function mapAdtTypeToSupported(
  adtType?: string,
): SupportedType | undefined {
  if (!adtType) {
    return undefined;
  }
  const normalized = adtType.toUpperCase();

  // Exact matches
  const map: Record<string, SupportedType> = {
    'DEVC/K': 'package',
    'DOMA/DD': 'domain',
    'DTEL/DE': 'dataElement',
    'TABL/DS': 'structure', // Note: ADT might return TABL/DS for structures sometimes
    'STRU/DT': 'structure',
    'STRU/DS': 'structure',
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
    'SRVB/SVB': 'serviceBinding',
    'BDEF/BDO': 'behaviorDefinition',
    'BIMP/BIM': 'behaviorImplementation',
    'BIMP/BI': 'behaviorImplementation',
    'BIMP/BO': 'behaviorImplementation',
    'ENHO/ENH': 'enhancement',
  };

  if (map[normalized]) {
    return map[normalized];
  }

  // Prefix matches
  if (normalized.startsWith('CLAS/')) return 'class';
  if (normalized.startsWith('INTF/')) return 'interface';
  if (normalized.startsWith('PROG/')) return 'program';
  if (normalized.startsWith('DDLS/')) return 'view';
  if (normalized.startsWith('DDLX/')) return 'metadataExtension';
  if (normalized.startsWith('SRVD/')) return 'serviceDefinition';
  if (normalized.startsWith('SRVB/')) return 'serviceBinding';
  if (normalized.startsWith('DOMA/')) return 'domain';
  if (normalized.startsWith('DTEL/')) return 'dataElement';
  if (normalized.startsWith('TABL/DS') || normalized.startsWith('STRU/'))
    return 'structure';
  if (normalized.startsWith('TABL/DT')) return 'table';
  if (normalized.startsWith('TTYP/')) return 'tableType';
  if (normalized.startsWith('FUGR/FF')) return 'functionModule';
  if (normalized.startsWith('FUGR/')) return 'functionGroup';
  if (normalized.startsWith('DEVC/')) return 'package';
  if (normalized.startsWith('BDEF/')) return 'behaviorDefinition';
  if (normalized.startsWith('BIMP/') || normalized.startsWith('BIMPL/'))
    return 'behaviorImplementation';
  if (normalized.startsWith('ENHO/')) return 'enhancement';

  return undefined;
}
