export function toBoolean(value?: string): boolean | undefined {
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
