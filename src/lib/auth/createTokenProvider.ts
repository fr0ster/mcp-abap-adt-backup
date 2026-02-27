import { AuthorizationCodeProvider } from '@mcp-abap-adt/auth-providers';
import type {
  IAuthorizationConfig,
  ITokenProvider,
} from '@mcp-abap-adt/interfaces';
import { NoopTokenProvider } from '../auth/NoopTokenProvider';
import type { createLogger } from '../cli/createLogger';
import { shouldEnableProviderLogger } from '../cli/shouldEnableProviderLogger';

export function createTokenProvider(
  authConfig?: IAuthorizationConfig | null,
  browserAuthPort?: number,
  logger?: ReturnType<typeof createLogger>,
): ITokenProvider {
  if (
    !authConfig ||
    !authConfig.uaaUrl ||
    !authConfig.uaaClientId ||
    !authConfig.uaaClientSecret
  ) {
    return new NoopTokenProvider();
  }

  return new AuthorizationCodeProvider({
    uaaUrl: authConfig.uaaUrl,
    clientId: authConfig.uaaClientId,
    clientSecret: authConfig.uaaClientSecret,
    refreshToken: authConfig.refreshToken,
    browser: 'system',
    redirectPort: browserAuthPort || 10001,
    logger: shouldEnableProviderLogger() ? logger : undefined,
  } as any);
}
