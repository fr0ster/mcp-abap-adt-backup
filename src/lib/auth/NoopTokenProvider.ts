import type { ITokenProvider, ITokenResult } from '@mcp-abap-adt/interfaces';

export class NoopTokenProvider implements ITokenProvider {
  async getTokens(): Promise<ITokenResult> {
    throw new Error(
      'Token provider is not configured. Ensure your destination has authorization settings or use an .env session with JWT.',
    );
  }
}
