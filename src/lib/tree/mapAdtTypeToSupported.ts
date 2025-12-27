import type { SupportedType } from '../types';

export function mapAdtTypeToSupported(
  adtType?: string,
): SupportedType | undefined {
  if (!adtType) {
    return undefined;
  }
  const normalized = adtType.toUpperCase();
  if (normalized === 'DEVC/K') return 'package';
  if (normalized === 'DOMA/DD') return 'domain';
  if (normalized === 'DTEL/DE') return 'dataElement';
  if (normalized === 'STRU/DS') return 'structure';
  if (normalized === 'TABL/DT') return 'table';
  if (normalized === 'TTYP/DT') return 'tableType';
  if (normalized === 'DDLS/DF') return 'view';
  if (normalized === 'CLAS/OC') return 'class';
  if (normalized === 'INTF/OI') return 'interface';
  if (normalized === 'PROG/P') return 'program';
  if (normalized === 'FUGR/F') return 'functionGroup';
  if (normalized === 'FUGR/FF') return 'functionModule';
  if (normalized === 'SRVD/SRV') return 'serviceDefinition';
  if (normalized === 'DDLS/EX') return 'metadataExtension';
  if (normalized === 'BDEF/BDEF') return 'behaviorDefinition';
  if (normalized === 'BDEF/BIMP') return 'behaviorImplementation';
  return undefined;
}
