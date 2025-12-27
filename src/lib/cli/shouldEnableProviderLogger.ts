import { isEnvEnabled } from './isEnvEnabled';

export function shouldEnableProviderLogger(): boolean {
  return (
    isEnvEnabled(process.env.DEBUG_PROVIDER) ||
    isEnvEnabled(process.env.DEBUG_AUTH_PROVIDERS) ||
    isEnvEnabled(process.env.DEBUG_AUTH_LOG)
  );
}
