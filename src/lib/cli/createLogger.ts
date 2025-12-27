export function createLogger(level: number) {
  return {
    debug: (message: string, meta?: unknown) => {
      if (level >= 3) {
        console.log(message, meta ?? '');
      }
    },
    info: (message: string, meta?: unknown) => {
      if (level >= 1) {
        console.log(message, meta ?? '');
      }
    },
    warn: (message: string, meta?: unknown) => {
      if (level >= 1) {
        console.warn(message, meta ?? '');
      }
    },
    error: (message: string, meta?: unknown) => {
      console.error(message, meta ?? '');
    },
  };
}
