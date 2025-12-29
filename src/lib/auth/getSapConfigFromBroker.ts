import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { AuthBroker } from '@mcp-abap-adt/auth-broker';
import {
  AbapServiceKeyStore,
  AbapSessionStore,
  EnvFileSessionStore,
} from '@mcp-abap-adt/auth-stores';
import type { SapConfig } from '@mcp-abap-adt/connection';
import type { ITokenRefresher } from '@mcp-abap-adt/interfaces';
import type { createLogger } from '../cli/createLogger';
import { shouldEnableBrokerLogger } from '../cli/shouldEnableBrokerLogger';
import { shouldEnableStoreLogger } from '../cli/shouldEnableStoreLogger';
import { createTokenProvider } from './createTokenProvider';

export async function getSapConfigFromBroker(options: {
  destination?: string;
  envPath?: string;
  authRoot?: string;
  logger: ReturnType<typeof createLogger>;
}): Promise<{ config: SapConfig; tokenRefresher?: ITokenRefresher }> {
  const { logger } = options;
  const brokerLogger = shouldEnableBrokerLogger() ? logger : undefined;
  const storeLogger = shouldEnableStoreLogger() ? logger : undefined;

  const destination = options.destination || 'env';
  if (options.envPath) {
    const sessionStore = new EnvFileSessionStore(options.envPath, storeLogger);
    return getConfigWithStores({
      destination,
      sessionStore,
      serviceKeyStore: undefined,
      logger,
      brokerLogger,
    });
  }

  const roots = resolveAuthRoots(options.authRoot);
  const { sessionDir, serviceKeyDir } = resolveStoreDirs(roots, destination);
  const sessionStore = new AbapSessionStore(sessionDir, storeLogger);
  const serviceKeyStore = new AbapServiceKeyStore(serviceKeyDir, storeLogger);
  return getConfigWithStores({
    destination,
    sessionStore,
    serviceKeyStore,
    logger,
    brokerLogger,
  });
}

function resolveAuthRoots(authRoot?: string): string[] {
  if (authRoot) {
    return [path.resolve(authRoot)];
  }
  const envPath = process.env.AUTH_BROKER_PATH;
  if (envPath) {
    return envPath
      .split(/[:;]/)
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0)
      .map((entry) => path.resolve(entry));
  }
  if (process.platform === 'win32') {
    return [path.join(os.homedir(), 'Documents', 'mcp-abap-adt')];
  }
  return [path.join(os.homedir(), '.config', 'mcp-abap-adt')];
}

function resolveStoreDirs(
  roots: string[],
  destination: string,
): { sessionDir: string; serviceKeyDir: string } {
  const candidates = roots.map((root) => {
    const normalized = path.resolve(root);
    if (normalized.endsWith(`${path.sep}sessions`)) {
      return {
        sessionDir: normalized,
        serviceKeyDir: path.join(path.dirname(normalized), 'service-keys'),
      };
    }
    if (normalized.endsWith(`${path.sep}service-keys`)) {
      return {
        sessionDir: path.join(path.dirname(normalized), 'sessions'),
        serviceKeyDir: normalized,
      };
    }
    return {
      sessionDir: path.join(normalized, 'sessions'),
      serviceKeyDir: path.join(normalized, 'service-keys'),
    };
  });

  for (const candidate of candidates) {
    const sessionFile = path.join(candidate.sessionDir, `${destination}.env`);
    const serviceKeyFile = path.join(
      candidate.serviceKeyDir,
      `${destination}.json`,
    );
    if (fs.existsSync(sessionFile) || fs.existsSync(serviceKeyFile)) {
      return candidate;
    }
  }

  return candidates[0];
}

async function getConfigWithStores(options: {
  destination: string;
  sessionStore: AbapSessionStore | EnvFileSessionStore;
  serviceKeyStore?: AbapServiceKeyStore;
  logger: ReturnType<typeof createLogger>;
  brokerLogger?: ReturnType<typeof createLogger>;
}): Promise<{ config: SapConfig; tokenRefresher?: ITokenRefresher }> {
  const { destination, sessionStore, serviceKeyStore, logger, brokerLogger } =
    options;
  const sessionAuthConfig =
    destination === 'env'
      ? null
      : await sessionStore.getAuthorizationConfig(destination);
  const serviceKeyAuthConfig =
    destination === 'env' || !serviceKeyStore?.getAuthorizationConfig
      ? null
      : await serviceKeyStore.getAuthorizationConfig(destination);
  const authConfig = sessionAuthConfig || serviceKeyAuthConfig;

  const broker = new AuthBroker(
    {
      sessionStore,
      serviceKeyStore,
      tokenProvider: createTokenProvider(authConfig, logger),
    },
    undefined,
    brokerLogger,
  );

  const session = await sessionStore.loadSession(destination);
  let connection = await broker.getConnectionConfig(destination);
  if (!connection && authConfig && destination !== 'env') {
    await broker.getToken(destination);
    connection = await broker.getConnectionConfig(destination);
  }
  if (!connection) {
    throw new Error(`Missing connection config for destination ${destination}`);
  }

  if (
    !connection.authorizationToken &&
    !connection.username &&
    !connection.password &&
    authConfig &&
    destination !== 'env'
  ) {
    await broker.getToken(destination);
    connection = await broker.getConnectionConfig(destination);
    if (!connection) {
      throw new Error(
        `Missing connection config for destination ${destination}`,
      );
    }
  }

  const resolvedAuthType = connection.authorizationToken
    ? 'jwt'
    : connection.username && connection.password
      ? 'basic'
      : authConfig && destination !== 'env'
        ? 'jwt'
        : connection.authType || 'basic';
  const serviceUrl = connection.serviceUrl || session?.serviceUrl;
  if (!serviceUrl) {
    throw new Error(`Missing service URL for destination ${destination}`);
  }

  const config: SapConfig = {
    url: serviceUrl,
    authType: resolvedAuthType,
  };

  if (resolvedAuthType === 'jwt') {
    if (!connection.authorizationToken) {
      throw new Error(`Missing JWT token for destination ${destination}`);
    }
    config.jwtToken = connection.authorizationToken;
  } else {
    if (!connection.username || !connection.password) {
      throw new Error(
        `Missing username/password for destination ${destination}`,
      );
    }
    config.username = connection.username;
    config.password = connection.password;
  }

  const tokenRefresher =
    resolvedAuthType === 'jwt'
      ? broker.createTokenRefresher(destination)
      : undefined;

  return { config, tokenRefresher };
}
