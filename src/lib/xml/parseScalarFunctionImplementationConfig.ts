export function parseScalarFunctionImplementationConfig(source: string): {
  scalarFunctionName?: string;
  engineValue?: 'sqlEngine' | 'amdpEngine';
} {
  try {
    const parsed = JSON.parse(source) as Record<string, unknown>;
    const scalarFunctionName =
      typeof parsed.scalarFunctionName === 'string'
        ? parsed.scalarFunctionName
        : undefined;
    const rawEngine =
      typeof parsed.engine === 'string' ? parsed.engine : undefined;
    const engineValue: 'sqlEngine' | 'amdpEngine' =
      rawEngine === 'amdpEngine' ? 'amdpEngine' : 'sqlEngine';
    return { scalarFunctionName, engineValue };
  } catch {
    return {};
  }
}
