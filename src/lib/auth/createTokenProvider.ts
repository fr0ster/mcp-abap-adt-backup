import type { TokenProviderFactory } from '@mcp-abap-adt/auth-broker';
import {
  AuthorizationCodeProvider,
  browserCallbackStrategy,
} from '@mcp-abap-adt/auth-providers';
import type { IRefreshableTokenProvider } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { shouldEnableProviderLogger } from '../cli/shouldEnableProviderLogger';
import { NoopTokenProvider } from './NoopTokenProvider';

/** The callback port the CLI has always used; `--browser-auth-port` overrides it. */
export const DEFAULT_BROWSER_AUTH_PORT = 10001;

/**
 * How long a browser login may take. The provider's own default is 30 s, which
 * a person completing an SSO or MFA prompt routinely overruns.
 */
export const BROWSER_LOGIN_TIMEOUT_MS = 180_000;

/**
 * The provider factory handed to the broker.
 *
 * The broker seeds it per destination with what the stores hold: the UAA
 * credentials and the refresh token, and the token the session stored last.
 * A login opens the system browser on the given callback port — the CLI is
 * interactive, and a user running it expects the browser, as it always did.
 */
export function createTokenProviderFactory(
  browserAuthPort: number = DEFAULT_BROWSER_AUTH_PORT,
  logger?: ILogger,
): TokenProviderFactory {
  return (_destination, authConfig, connConfig): IRefreshableTokenProvider => {
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
      accessToken: connConfig.authorizationToken,
      authorization: browserCallbackStrategy({
        browser: 'system',
        port: browserAuthPort,
        timeoutMs: BROWSER_LOGIN_TIMEOUT_MS,
      }),
      logger: shouldEnableProviderLogger() ? logger : undefined,
    });
  };
}
