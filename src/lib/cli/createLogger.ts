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
      // Robust detection of "expected" missing object errors from ADT clients
      const metaObj = meta && typeof meta === 'object' ? (meta as any) : {};
      const fullMsg = (
        message +
        (metaObj.message || '') +
        JSON.stringify(metaObj)
      ).toLowerCase();

      const isExpectedNotFound =
        metaObj.status === 404 ||
        metaObj.status === 410 ||
        /not found/i.test(fullMsg) ||
        /does not exist/i.test(fullMsg) ||
        /ExceptionResourceNotFound/i.test(fullMsg) ||
        (/failed for/i.test(fullMsg) && /404/i.test(fullMsg));

      if (isExpectedNotFound) {
        // Only show detailed ADT failures at maximum verbosity (-vvv)
        if (level >= 3) {
          console.log(`[DEBUG] Object missing in system: ${message}`);
        }
        return;
      }

      const formatted = formatLogMeta(meta);
      console.error(message, formatted || '');
    },
  };
}
