import type { SupportedType } from '../types';

export type VerifyStatus =
  | 'ok'
  | 'missing'
  | 'type-mismatch'
  | 'package-mismatch'
  | 'source-mismatch'
  | 'unsupported'
  | 'error';

export interface VerifyEntry {
  type: SupportedType;
  name: string;
  functionGroupName?: string;
  status: VerifyStatus;
  expectedPackage?: string;
  actualPackage?: string;
  message?: string;
}

export interface VerifySummary {
  total: number;
  ok: number;
  missing: number;
  typeMismatch: number;
  packageMismatch: number;
  sourceMismatch: number;
  unsupported: number;
  error: number;
  conflicts: number;
  create?: number;
  update?: number;
  skip?: number;
}
