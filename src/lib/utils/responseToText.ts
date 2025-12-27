export function responseToText(response?: {
  data?: unknown;
}): string | undefined {
  if (!response) {
    return undefined;
  }
  return typeof response.data === 'string'
    ? response.data
    : JSON.stringify(response.data);
}
