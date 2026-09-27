import type { AgentOptions } from 'node:https';
import {
  AdtCloudConnector,
  AdtOnPremConnector,
  BasicAuthProvider,
  CloudHttpTransport,
  LegacyOnPremHttpTransport,
  OnPremHttpTransport,
  type SapConfig,
  TokenAuthProvider,
} from '@mcp-abap-adt/connection';
import type {
  IAuthProvider,
  ITokenRefresher,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';

/**
 * Which kind of system the CLI is dialling.
 *
 * Stated, never worked out: the cloud and on-prem connectors release a session
 * differently, and the server cannot be asked which one it is — the cloud
 * session resource answers on on-prem too, and its `DELETE` there leaves the
 * session open. `legacy` is on-prem below BASIS 7.50, where the session-type
 * header sends locks to session memory instead of the enqueue server.
 */
export type SystemType = 'cloud' | 'onprem' | 'legacy';

const SYSTEM_TYPES: readonly SystemType[] = ['cloud', 'onprem', 'legacy'];

/**
 * The system type from `--system-type`, else `SAP_SYSTEM_TYPE` (which an
 * `--env` file may set). Neither the URL nor the authentication decides it: a
 * bearer token against on-prem and a basic user against cloud are both
 * ordinary.
 */
export function resolveSystemType(stated?: string): SystemType {
  const value = (stated ?? process.env.SAP_SYSTEM_TYPE ?? '')
    .split('#')[0]
    .trim()
    .toLowerCase();
  if ((SYSTEM_TYPES as readonly string[]).includes(value)) {
    return value as SystemType;
  }
  throw new Error(
    value
      ? `Unknown system type "${value}": use cloud, onprem or legacy.`
      : 'The target system type is not stated. Pass --system-type cloud|onprem|legacy, ' +
          'or set SAP_SYSTEM_TYPE in the environment or the --env file. It is not ' +
          'derived from the URL or the authentication type.',
  );
}

export type AdtConnection = AdtCloudConnector | AdtOnPremConnector;

/**
 * The connection for one system, built explicitly and not yet connected —
 * the caller runs `connect()` before the first request and `disconnect()`
 * when it is done.
 */
export function createConnection(
  config: SapConfig,
  systemType: SystemType,
  tokenRefresher?: ITokenRefresher,
  logger?: ILogger,
): AdtConnection {
  const credential = credentialFor(config, tokenRefresher);
  // Evaluated when the wire needs it: the credential prepares its material
  // during connect(), so a value read now would be empty.
  const material = () => credential.transportMaterial() as AgentOptions;
  // `client` routes every request to the client that was asked for; without
  // it SAP answers with the system default.
  const wire = { client: config.client, baseUrl: config.url };

  if (systemType === 'cloud') {
    return new AdtCloudConnector(
      config,
      credential,
      new CloudHttpTransport(material, logger, wire),
      logger,
    );
  }
  const transport =
    systemType === 'legacy'
      ? new LegacyOnPremHttpTransport(material, logger, wire)
      : new OnPremHttpTransport(material, logger, wire);
  return new AdtOnPremConnector(config, credential, transport, logger);
}

function credentialFor(
  config: SapConfig,
  tokenRefresher?: ITokenRefresher,
): IAuthProvider {
  if (config.authType === 'jwt') {
    if (tokenRefresher) return new TokenAuthProvider(tokenRefresher);
    if (!config.jwtToken) {
      throw new Error('No token for a JWT connection: log in first.');
    }
    return new TokenAuthProvider(config.jwtToken);
  }
  if (!config.username || !config.password) {
    throw new Error('Basic authentication needs a username and a password.');
  }
  return new BasicAuthProvider(config.username, config.password);
}

/**
 * Give the session back and wait, briefly, for the goodbye to leave: the CLI
 * exits right after this, and a logoff still being assembled would be dropped.
 */
export async function closeConnection(
  connection: AdtConnection,
): Promise<void> {
  await connection.disconnect();
  await connection.flushGoodbye(5000);
}
