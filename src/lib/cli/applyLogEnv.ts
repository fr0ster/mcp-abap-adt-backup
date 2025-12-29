export function applyLogEnv(level: number): void {
  if (level >= 3) {
    process.env.LOG_LEVEL = 'debug';
    process.env.DEBUG_BROKER = 'true';
    process.env.DEBUG_AUTH_BROKER = 'true';
    process.env.DEBUG_PROVIDER = 'true';
    process.env.DEBUG_AUTH_PROVIDERS = 'true';
    process.env.DEBUG_STORES = 'true';
    process.env.DEBUG_AUTH_STORES = 'true';
    process.env.DEBUG_ADT_LIBS = 'true';
    process.env.DEBUG_CONNECTORS = 'true';
    return;
  }
  if (level >= 2) {
    process.env.LOG_LEVEL = 'info';
    process.env.DEBUG_BROKER = 'true';
    process.env.DEBUG_AUTH_BROKER = 'true';
    process.env.DEBUG_PROVIDER = 'false';
    process.env.DEBUG_AUTH_PROVIDERS = 'false';
    process.env.DEBUG_STORES = 'false';
    process.env.DEBUG_AUTH_STORES = 'false';
    process.env.DEBUG_CONNECTORS = 'false';
    process.env.DEBUG_ADT_LIBS = 'true';
    return;
  }
  if (level >= 1) {
    process.env.LOG_LEVEL = 'info';
    process.env.DEBUG_BROKER = 'false';
    process.env.DEBUG_AUTH_BROKER = 'false';
    process.env.DEBUG_PROVIDER = 'false';
    process.env.DEBUG_AUTH_PROVIDERS = 'false';
    process.env.DEBUG_STORES = 'false';
    process.env.DEBUG_AUTH_STORES = 'false';
    process.env.DEBUG_CONNECTORS = 'false';
    process.env.DEBUG_ADT_LIBS = 'false';
    return;
  }
  process.env.LOG_LEVEL = 'error';
  process.env.DEBUG_BROKER = 'false';
  process.env.DEBUG_AUTH_BROKER = 'false';
  process.env.DEBUG_PROVIDER = 'false';
  process.env.DEBUG_AUTH_PROVIDERS = 'false';
  process.env.DEBUG_STORES = 'false';
  process.env.DEBUG_AUTH_STORES = 'false';
  process.env.DEBUG_CONNECTORS = 'false';
  process.env.DEBUG_ADT_LIBS = 'false';
}
