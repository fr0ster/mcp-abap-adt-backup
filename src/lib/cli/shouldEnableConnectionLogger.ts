import { isEnvEnabled } from './isEnvEnabled';

export function shouldEnableConnectionLogger(): boolean {
  return isEnvEnabled(process.env.DEBUG_CONNECTORS);
}
