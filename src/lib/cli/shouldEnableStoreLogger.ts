import { isEnvEnabled } from './isEnvEnabled';

export function shouldEnableStoreLogger(): boolean {
  return (
    isEnvEnabled(process.env.DEBUG_STORES) ||
    isEnvEnabled(process.env.DEBUG_AUTH_STORES) ||
    isEnvEnabled(process.env.DEBUG_AUTH_LOG)
  );
}
