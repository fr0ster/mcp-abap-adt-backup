function maskToken(token: string): string {
  const trimmed = token.trim();
  if (trimmed.length <= 12) {
    return trimmed;
  }
  return `${trimmed.slice(0, 6)}...${trimmed.slice(-6)}`;
}

export function redactText(input: string): string {
  const bearerRegex = /\bBearer\s+([A-Za-z0-9-_.]+)/gi;
  const jwtRegex =
    /\b[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\b/g;
  let output = input.replace(bearerRegex, (_match, token) => {
    return `Bearer ${maskToken(token)}`;
  });
  output = output.replace(jwtRegex, (token) => maskToken(token));
  return output;
}

export function safeStringify(value: unknown): string {
  const replacer = (key: string, val: unknown): unknown => {
    if (typeof val === 'string') {
      if (/(token|authorization|clientsecret|password|refresh)/i.test(key)) {
        return redactText(val);
      }
      return redactText(val);
    }
    return val;
  };
  try {
    return JSON.stringify(value, replacer);
  } catch {
    return String(value);
  }
}

export function formatLogMeta(meta: unknown): string {
  if (meta === undefined || meta === null) {
    return '';
  }
  const record = meta as {
    isAxiosError?: boolean;
    message?: string;
    code?: string;
    response?: { status?: number };
    config?: { url?: string; method?: string };
  };
  if (record && record.isAxiosError) {
    return safeStringify({
      message: record.message,
      code: record.code,
      status: record.response?.status,
      url: record.config?.url,
      method: record.config?.method,
    });
  }
  if (meta instanceof Error) {
    return redactText(meta.message);
  }
  if (typeof meta === 'string') {
    return redactText(meta);
  }
  return safeStringify(meta);
}
