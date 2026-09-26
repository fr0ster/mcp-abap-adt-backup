import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { AuthBroker } from '@mcp-abap-adt/auth-broker';
import { BrowserAuthError } from '@mcp-abap-adt/auth-providers';
import {
  AbapServiceKeyStore,
  AbapSessionStore,
  EnvFileSessionStore,
} from '@mcp-abap-adt/auth-stores';
import type { SapConfig } from '@mcp-abap-adt/connection';
import type { ITokenRefresher } from '@mcp-abap-adt/interfaces-auth';
import type { IConnectionConfig } from '@mcp-abap-adt/interfaces-auth-sap';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { logVerbose } from '../cli/logVerbose';
import { shouldEnableBrokerLogger } from '../cli/shouldEnableBrokerLogger';
import { shouldEnableStoreLogger } from '../cli/shouldEnableStoreLogger';
import { createTokenProviderFactory } from './createTokenProvider';

export interface SapAuthResult {
  config: SapConfig;
  /** Present for a bearer-token connection whose token the broker can renew. */
  tokenRefresher?: ITokenRefresher;
}

export async function getSapConfigFromBroker(options: {
  destination?: string;
  envPath?: string;
  authRoot?: string;
  browserAuthPort?: number;
  logger: ILogger;
}): Promise<SapAuthResult> {
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

  const broker = new AuthBroker(
    {
      sessionStore,
      serviceKeyStore,
      provider: createTokenProviderFactory(options.browserAuthPort, logger),
    },
    brokerLogger,
  );

  const authConfig = await broker.getAuthorizationConfig(destination);

  // 3. Try to get connection.
  let connection = await broker.getConnectionConfig(destination);

  // Perform authentication if session is missing but auth config is available
  if (!connection && authConfig && destination !== 'env') {
    logVerbose(1, `Initiating authentication for ${destination}...`);
    await obtainToken(broker, destination);
    connection = await broker.getConnectionConfig(destination);
  }

  // Fallback to process.env if not found in stores
  if (
    !connection &&
    (destination === 'env' || destination === 'SAP' || options.envPath)
  ) {
    connection = connectionFromEnv();
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
    await obtainToken(broker, destination);
    connection = (await broker.getConnectionConfig(destination)) ?? connection;
  }

  const authType =
    connection.authType === 'basic' || connection.authType === 'jwt'
      ? connection.authType
      : connection.authorizationToken
        ? 'jwt'
        : connection.username && connection.password
          ? 'basic'
          : 'jwt';

  const serviceUrl = connection.serviceUrl;
  if (!serviceUrl) {
    throw new Error(`Missing service URL for destination ${destination}`);
  }

  const config: SapConfig = { url: serviceUrl, authType };
  const client = connection.sapClient || process.env.SAP_CLIENT;
  if (client) config.client = client;

  if (authType === 'jwt') {
    config.jwtToken = connection.authorizationToken;
  } else {
    config.username = connection.username;
    config.password = connection.password;
  }

  // A renewable token only where the broker can renew it: with UAA
  // credentials behind the destination. An .env token alone has nothing to
  // renew from, and handing the connection a refresher that can only fail
  // would replace a clear 401 with a provider error.
  const tokenRefresher =
    authType === 'jwt' && authConfig
      ? broker.createTokenRefresher(destination)
      : undefined;

  return { config, tokenRefresher };
}

/** A login, with a failed browser login named as such. */
async function obtainToken(
  broker: AuthBroker,
  destination: string,
): Promise<void> {
  try {
    await broker.getToken(destination);
  } catch (error) {
    if (error instanceof BrowserAuthError) {
      throw new Error(
        `Browser login for ${destination} did not complete: ${error.message}`,
        { cause: error },
      );
    }
    throw error;
  }
}

function connectionFromEnv(): IConnectionConfig | null {
  const url = process.env.SAP_URL || process.env.SAP_SERVICEURL;
  if (!url) return null;
  const token = process.env.SAP_JWT_TOKEN || process.env.SAP_TOKEN;
  const stated = (process.env.SAP_AUTH_TYPE || '').trim().toLowerCase();
  const authType: 'basic' | 'jwt' =
    stated === 'basic' || stated === 'jwt'
      ? stated
      : stated === 'xsuaa' || token
        ? 'jwt'
        : 'basic';
  return {
    serviceUrl: url,
    authorizationToken: token,
    username: process.env.SAP_USERNAME || process.env.SAP_USER,
    password: process.env.SAP_PASSWORD || process.env.SAP_PASS,
    sapClient: process.env.SAP_CLIENT,
    authType,
  };
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
