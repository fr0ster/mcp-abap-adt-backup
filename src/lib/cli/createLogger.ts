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
      const formatted = formatLogMeta(meta);
      console.error(message, formatted || '');
    },
  };
}
