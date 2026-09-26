import type {
  IRefreshableTokenProvider,
  ITokenResult,
} from '@mcp-abap-adt/interfaces-auth';

/**
 * The provider for a destination whose stores hold no UAA credentials.
 *
 * There is nothing to log in with, so asking for a token is an error that
 * names what is missing rather than a login attempt that cannot succeed.
 */
export class NoopTokenProvider implements IRefreshableTokenProvider {
  async getTokens(): Promise<ITokenResult> {
    throw new Error(
      'Token provider is not configured. Ensure your destination has authorization settings or use an .env session with JWT.',
    );
  }

  async refreshTokens(): Promise<ITokenResult> {
    return this.getTokens();
  }
}
