import { isEnvEnabled } from './isEnvEnabled';

export function shouldEnableBrokerLogger(): boolean {
  return (
    isEnvEnabled(process.env.DEBUG_BROKER) ||
    isEnvEnabled(process.env.DEBUG_AUTH_BROKER) ||
    isEnvEnabled(process.env.DEBUG_AUTH_LOG)
  );
}
