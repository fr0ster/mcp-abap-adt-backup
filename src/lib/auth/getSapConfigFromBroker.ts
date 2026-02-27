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
import type {
  IAuthorizationConfig,
  IConfig,
  ITokenRefresher,
} from '@mcp-abap-adt/interfaces';
import type { createLogger } from '../cli/createLogger';
import { logVerbose } from '../cli/logVerbose';
import { shouldEnableBrokerLogger } from '../cli/shouldEnableBrokerLogger';
import { shouldEnableStoreLogger } from '../cli/shouldEnableStoreLogger';
import { createTokenProvider } from './createTokenProvider';

export async function getSapConfigFromBroker(options: {
  destination?: string;
  envPath?: string;
  authRoot?: string;
  browserAuthPort?: number;
  logger: ReturnType<typeof createLogger>;
}): Promise<{ config: SapConfig; tokenRefresher?: ITokenRefresher }> {
  const { logger } = options;
  const brokerLogger = shouldEnableBrokerLogger() ? logger : undefined;
  const storeLogger = shouldEnableStoreLogger() ? logger : undefined;

  // 1. If --env-path is provided, we load it into process.env first
  if (options.envPath && fs.existsSync(options.envPath)) {
    const content = fs.readFileSync(options.envPath, 'utf8');
    const envVars = parseEnvContent(content);
    for (const [key, value] of Object.entries(envVars)) {
      process.env[key] = value;
    }
  }

  const destination = options.destination || 'env';
  const roots = resolveAuthRoots(options.authRoot);
  const { sessionDir, serviceKeyDir } = resolveStoreDirs(roots, destination);

  // 2. Initialize stores
  const sessionStore = options.envPath
    ? new EnvFileSessionStore(options.envPath, storeLogger)
    : new AbapSessionStore(sessionDir, storeLogger);

  const serviceKeyStore = new AbapServiceKeyStore(serviceKeyDir, storeLogger);

  // 3. Get authorization config from store
  const sessionAuthConfig = (await sessionStore.getAuthorizationConfig(
    destination,
  )) as IAuthorizationConfig | null;
  const serviceKeyAuthConfig = (await serviceKeyStore.getAuthorizationConfig(
    destination,
  )) as IAuthorizationConfig | null;
  const authConfig = sessionAuthConfig || serviceKeyAuthConfig;

  const broker = new AuthBroker(
    {
      sessionStore,
      serviceKeyStore,
      tokenProvider: createTokenProvider(
        authConfig,
        options.browserAuthPort,
        logger,
      ),
    },
    undefined,
    brokerLogger,
  );

  // 4. Try to get connection.
  let connection = (await broker.getConnectionConfig(destination)) as IConfig;

  // Perform authentication if session is missing but auth config is available
  if (!connection && authConfig && destination !== 'env') {
    logVerbose(1, `Initiating authentication for ${destination}...`);
    await broker.getToken(destination);
    connection = (await broker.getConnectionConfig(destination)) as IConfig;
  }

  // Fallback to process.env if not found in stores
  if (
    !connection &&
    (destination === 'env' || destination === 'SAP' || options.envPath)
  ) {
    const url = process.env.SAP_URL || process.env.SAP_SERVICEURL;
    if (url) {
      connection = {
        serviceUrl: url,
        authorizationToken: process.env.SAP_JWT_TOKEN || process.env.SAP_TOKEN,
        username: process.env.SAP_USERNAME || process.env.SAP_USER,
        password: process.env.SAP_PASSWORD || process.env.SAP_PASS,
        authType: (process.env.SAP_AUTH_TYPE ||
          (process.env.SAP_JWT_TOKEN ? 'jwt' : 'basic')) as any,
      } as any;
    }
  }

  if (!connection) {
    throw new Error(
      `Missing connection config for destination ${destination}. If using service keys, ensure the JSON file exists in ${serviceKeyDir}`,
    );
  }

  // If we have authConfig but no token in session, try to refresh/get it
  if (
    !connection.authorizationToken &&
    !connection.username &&
    authConfig &&
    destination !== 'env'
  ) {
    await broker.getToken(destination);
    connection = (await broker.getConnectionConfig(destination)) as IConfig;
  }

  const authType =
    connection.authType ||
    (connection.authorizationToken
      ? 'jwt'
      : connection.username && connection.password
        ? 'basic'
        : 'jwt');

  const serviceUrl = connection.serviceUrl;
  if (!serviceUrl) {
    throw new Error(`Missing service URL for destination ${destination}`);
  }

  const config: SapConfig = {
    url: serviceUrl,
    authType: authType as any,
  };

  if (authType === 'jwt') {
    config.jwtToken = connection.authorizationToken;
  } else {
    config.username = connection.username;
    config.password = connection.password;
  }

  const tokenRefresher =
    authType === 'jwt' ? broker.createTokenRefresher(destination) : undefined;

  return { config, tokenRefresher };
}

function parseEnvContent(content: string): Record<string, string> {
  const envVars: Record<string, string> = {};
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) continue;
    const key = trimmed.substring(0, eqIndex).trim();
    let value = trimmed.substring(eqIndex + 1).trim();
    value = value.replace(/^["']+|["']+$/g, '').trim();
    if (key) envVars[key] = value;
  }
  return envVars;
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
