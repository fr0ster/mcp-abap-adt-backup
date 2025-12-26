#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const { AuthBroker } = require('@mcp-abap-adt/auth-broker');
const {
  AuthorizationCodeProvider,
} = require('@mcp-abap-adt/auth-providers');
const {
  AbapServiceKeyStore,
  AbapSessionStore,
  EnvFileSessionStore,
  resolveSearchPaths,
} = require('@mcp-abap-adt/auth-stores');
const { createAbapConnection } = require('@mcp-abap-adt/connection');
const { AdtClient } = require('@mcp-abap-adt/adt-clients');

class NoopTokenProvider {
  async getTokens() {
    throw new Error(
      'Token provider is not configured. Ensure your destination has authorization settings.',
    );
  }
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith('--')) {
      continue;
    }
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith('--')) {
      args[key] = true;
    } else {
      args[key] = next;
      i += 1;
    }
  }
  return args;
}

function buildLogger(verbose) {
  return {
    debug: (message, meta) => {
      if (verbose) {
        console.log(message, meta ?? '');
      }
    },
    info: (message, meta) => {
      if (verbose) {
        console.log(message, meta ?? '');
      }
    },
    warn: (message, meta) => {
      console.warn(message, meta ?? '');
    },
    error: (message, meta) => {
      console.error(message, meta ?? '');
    },
  };
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function writeDump(outDir, name, response) {
  const filePath = path.join(outDir, name);
  const data =
    typeof response.data === 'string'
      ? response.data
      : JSON.stringify(response.data, null, 2);
  fs.writeFileSync(filePath, data, 'utf8');
  return filePath;
}

function isNotAcceptable(error) {
  return (
    typeof error === 'object' &&
    error !== null &&
    'response' in error &&
    typeof error.response?.status === 'number' &&
    error.response.status === 406
  );
}

async function dumpWithFallback({ name, outDir, primary, fallback }) {
  try {
    const response = await primary();
    console.log(`${name}: ${writeDump(outDir, `${name}.xml`, response)}`);
    return;
  } catch (error) {
    if (!fallback || !isNotAcceptable(error)) {
      console.warn(`${name}: failed`, error?.message || error);
      return;
    }
  }

  try {
    const response = await fallback();
    console.log(`${name}: ${writeDump(outDir, `${name}.xml`, response)}`);
  } catch (error) {
    console.warn(`${name}: failed after fallback`, error?.message || error);
  }
}

function createTokenProvider(authConfig, browser) {
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
    browser,
  });
}

async function getConnectionConfig(options, logger) {
  const searchPaths = resolveSearchPaths(options.authRoot);
  const primaryPath = searchPaths[0];
  if (!primaryPath) {
    throw new Error('No auth search paths resolved');
  }
  const sessionStore = options.envPath
    ? new EnvFileSessionStore(options.envPath, logger)
    : new AbapSessionStore(primaryPath, logger);
  const serviceKeyStore = options.envPath
    ? undefined
    : new AbapServiceKeyStore(primaryPath, logger);
  const destination = options.destination || 'env';

  const authConfig =
    (await sessionStore
      .getAuthorizationConfig(destination)
      .catch(() => null)) ||
    (serviceKeyStore
      ? await serviceKeyStore
          .getAuthorizationConfig(destination)
          .catch(() => null)
      : null);
  const tokenProvider = createTokenProvider(authConfig, options.browser);
  const broker = new AuthBroker(
    {
      sessionStore,
      serviceKeyStore,
      tokenProvider,
    },
    options.browser,
    logger,
  );

  const connConfig = await broker.getConnectionConfig(destination);
  if (!connConfig?.serviceUrl) {
    throw new Error(`Missing connection config for destination ${destination}`);
  }
  const resolvedAuthType =
    connConfig.authType ||
    (connConfig.username || connConfig.password ? 'basic' : undefined) ||
    'jwt';

  const config = {
    url: connConfig.serviceUrl,
    authType: resolvedAuthType,
    client: connConfig.sapClient,
  };

  if (resolvedAuthType === 'jwt') {
    const token = await broker.getToken(destination);
    if (!token) {
      throw new Error(`Missing JWT token for destination ${destination}`);
    }
    config.jwtToken = token;
  } else {
    if (!connConfig.username || !connConfig.password) {
      throw new Error(
        `Missing username/password for destination ${destination}`,
      );
    }
    config.username = connConfig.username;
    config.password = connConfig.password;
  }

  const tokenRefresher =
    resolvedAuthType === 'jwt'
      ? broker.createTokenRefresher(destination)
      : undefined;

  return { config, tokenRefresher };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.destination && !args.env) {
    throw new Error('Missing --destination (or provide --env)');
  }
  if (!args.package) {
    throw new Error('Missing --package');
  }

  const outDir = args['out-dir'] || '/tmp/adt-xml-dumps';
  const verbose = Boolean(args.verbose);
  const logger = buildLogger(verbose);

  const { config, tokenRefresher } = await getConnectionConfig(
    {
      destination: args.destination,
      envPath: args.env,
      authRoot: args['auth-root'],
      browser: args.browser || 'chrome',
    },
    logger,
  );

  const connection = createAbapConnection(
    config,
    console,
    undefined,
    tokenRefresher,
  );
  const utils = new AdtClient(connection, console).getUtils();
  ensureDir(outDir);

  const packageName = args.package.toString().toUpperCase();

  console.log(`Dumping XML for package ${packageName} into ${outDir}`);

  const nodeId = args['node-id'] || '000000';
  await dumpWithFallback({
    name: 'nodeStructure',
    outDir,
    primary: () =>
      utils.fetchNodeStructure('DEVC/K', packageName, nodeId, true),
    fallback: () =>
      connection.makeAdtRequest({
        url: '/sap/bc/adt/repository/nodestructure',
        method: 'POST',
        timeout: 30000,
        data: `<?xml version="1.0" encoding="UTF-8"?><asx:abap xmlns:asx="http://www.sap.com/abapxml" version="1.0">
<asx:values>
<DATA>
<TV_NODEKEY>${nodeId}</TV_NODEKEY>
</DATA>
</asx:values>
</asx:abap>`,
        params: {
          parent_type: 'DEVC/K',
          parent_name: packageName,
          parent_tech_name: packageName,
          withShortDescriptions: 'true',
        },
      }),
  });

  await dumpWithFallback({
    name: 'objectStructure',
    outDir,
    primary: () => utils.getObjectStructure('DEVC/K', packageName),
  });

  const vfMethodName =
    args['virtual-folder-method'] || 'getVirtualFoldersContents';
  const vfMethod = utils[vfMethodName];
  if (typeof vfMethod === 'function') {
    let params = { objectSearchPattern: packageName };
    if (typeof args['virtual-folder-params'] === 'string') {
      try {
        params = JSON.parse(args['virtual-folder-params']);
      } catch (_error) {
        throw new Error('Invalid --virtual-folder-params JSON');
      }
    }
    await dumpWithFallback({
      name: 'virtualFolder',
      outDir,
      primary: () => vfMethod.call(utils, params),
    });
  } else {
    console.warn(
      `virtualFolder skipped: method ${vfMethodName} not found on AdtUtils`,
    );
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
