import { isEnvEnabled } from './isEnvEnabled';

export function shouldEnableAdtLogger(): boolean {
  return (
    isEnvEnabled(process.env.DEBUG_ADT_LIBS) ||
    isEnvEnabled(process.env.DEBUG_ADT_TESTS) ||
    isEnvEnabled(process.env.DEBUG_ADT_E2E_TESTS) ||
    isEnvEnabled(process.env.DEBUG_ADT_HELPER_TESTS)
  );
}
