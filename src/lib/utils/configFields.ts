import type { BackupConfig } from '../types';

/*
 * Reading a backed-up config (YAML, so `Record<string, unknown>`) into the
 * typed configs adt-clients takes. Each field is checked, not cast: a value of
 * the wrong kind is absent rather than smuggled into a contract type.
 */

export function stringField(
  config: BackupConfig,
  key: string,
): string | undefined {
  const value = config[key];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

export function booleanField(
  config: BackupConfig,
  key: string,
): boolean | undefined {
  const value = config[key];
  return typeof value === 'boolean' ? value : undefined;
}

/** `value` when it is one of `allowed`, else `undefined`. */
export function oneOf<T extends string>(
  value: unknown,
  allowed: readonly T[],
): T | undefined {
  return typeof value === 'string' &&
    (allowed as readonly string[]).includes(value)
    ? (value as T)
    : undefined;
}
