import { formatLogMeta } from './redact';

export function createLogger(level: number) {
  return {
    debug: (message: string, meta?: unknown) => {
      if (level >= 3) {
        const formatted = formatLogMeta(meta);
        console.log(message, formatted || '');
      }
    },
    info: (message: string, meta?: unknown) => {
      if (level >= 1) {
        const formatted = formatLogMeta(meta);
        console.log(message, formatted || '');
      }
    },
    warn: (message: string, meta?: unknown) => {
      if (level >= 1) {
        const formatted = formatLogMeta(meta);
        console.warn(message, formatted || '');
      }
    },
    error: (message: string, meta?: unknown) => {
      // Silence 404 errors as they are expected during verify/restore missing objects
      if (meta && typeof meta === 'object' && (meta as any).status === 404) {
        if (level >= 3) {
          const formatted = formatLogMeta(meta);
          console.log(message, formatted || '');
        }
        return;
      }
      const formatted = formatLogMeta(meta);
      console.error(message, formatted || '');
    },
  };
}
