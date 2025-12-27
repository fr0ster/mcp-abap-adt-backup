export function parseBehaviorDefinitionFromClass(
  source?: string,
): string | undefined {
  if (!source) {
    return undefined;
  }
  const match = source.match(/FOR\\s+BEHAVIOR\\s+OF\\s+([A-Z0-9_/]+)/i);
  return match ? match[1] : undefined;
}
