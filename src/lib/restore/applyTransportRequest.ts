export function applyTransportRequest<T extends Record<string, unknown>>(
  config: T,
  transportRequest?: string,
): T {
  if (!transportRequest || transportRequest.trim().length === 0) {
    return config;
  }
  return {
    ...config,
    transportRequest: transportRequest.trim(),
  };
}
