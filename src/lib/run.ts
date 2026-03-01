import * as fs from 'node:fs';
import * as path from 'node:path';
import type { ObjectReference } from '@mcp-abap-adt/adt-clients';
import { AdtClient, getSystemInformation } from '@mcp-abap-adt/adt-clients';
import { createAbapConnection } from '@mcp-abap-adt/connection';
import YAML from 'yaml';
import { getSapConfigFromBroker } from './auth/getSapConfigFromBroker';
import { backupObject } from './backup/backupObject';
import { readMetadataXmlForType } from './backup/readMetadataXmlForType';
import { readSourceText } from './backup/readSourceText';
import { applyLogEnv } from './cli/applyLogEnv';
import { createLogger } from './cli/createLogger';
import { getVerbosity } from './cli/getVerbosity';
import { logVerbose } from './cli/logVerbose';
import { parseArgs } from './cli/parseArgs';
import { shouldEnableAdtLogger } from './cli/shouldEnableAdtLogger';
import { shouldEnableConnectionLogger } from './cli/shouldEnableConnectionLogger';
import { usage } from './cli/usage';
import { computeBackupChecksum } from './crypto/computeBackupChecksum';
import { computeCodeChecksum } from './crypto/computeCodeChecksum';
import { decodeBase64 } from './crypto/decodeBase64';
import { encodeBase64 } from './crypto/encodeBase64';
import { updateTreeChecksums } from './crypto/updateTreeChecksums';
import { verifyBackupChecksum } from './crypto/verifyBackupChecksum';
import { verifyTreeChecksums } from './crypto/verifyTreeChecksums';
import { collectTreeDependencies } from './dependencies/collectTreeDependencies';
import { analyzeDependencies } from './restore/analyzeDependencies';
import { restoreTreeBackup } from './restore/restoreTreeBackup';
import { verbosityState } from './state/verbosity';
import { buildPackageBackupTree } from './tree/buildPackageBackupTree';
import { enrichTreeNode } from './tree/enrichTreeNode';
import { findNodeInTree } from './tree/findNodeInTree';
import { flattenTree } from './tree/flattenTree';
import { getNodeObjectId } from './tree/getNodeObjectId';
import type {
  BackupFile,
  BackupObject,
  BackupTreeFile,
  BackupTreeNode,
  RestoreMode,
  RestorePlan,
} from './types';
import { diffUnified } from './utils/diffUnified';
import { formatObjectSpec } from './utils/formatObjectSpec';
import { parseObjectSpec } from './utils/parseObjectSpec';
import { formatVerifyResultsText } from './verify/formatVerifyResultsText';
import { verifyBackup } from './verify/verifyBackup';
import { extractMetadata } from './xml/extractMetadata';

export async function run(): Promise<void> {
  const argv = process.argv.slice(2);
  const args = parseArgs(argv.slice(1));
  verbosityState.level =
    typeof args.verbosity === 'number' ? args.verbosity : getVerbosity(argv);
  const logger = createLogger(verbosityState.level);
  const command = argv[0];
  const logFile = typeof args['log-file'] === 'string' ? args['log-file'] : '';
  if (logFile) {
    enableLogFile(logFile);
  }
  applyLogEnv(verbosityState.level);
  const debugAdt = Boolean(args['debug-adt']);
  if (debugAdt) {
    process.env.DEBUG_ADT_LIBS = 'true';
    process.env.DEBUG_CONNECTORS = 'true';
  }

  const isHelp =
    args.help ||
    argv.includes('-h') ||
    argv.includes('--help') ||
    command === 'help';
  if (!command || (isHelp && !argv[1]) || (command === 'help' && !argv[1])) {
    console.log(usage());
    process.exit(0);
  }

  if (isHelp) {
    const helpCommand = command === 'help' ? argv[1] : command;
    console.log(usage(helpCommand));
    process.exit(0);
  }

  const isMcp = Boolean(args.mcp);
  const isEnv = Boolean(args.env);
  const envPathArg =
    typeof args['env-path'] === 'string' ? args['env-path'] : undefined;

  let destination: string | undefined;
  let envPath: string | undefined;

  if (envPathArg) {
    envPath = envPathArg;
    destination = 'env';
  } else if (isEnv) {
    destination = 'env';
  } else if (isMcp) {
    destination = 'SAP';
  } else {
    destination =
      typeof args.destination === 'string'
        ? args.destination
        : typeof args.target === 'string'
          ? args.target
          : undefined;
  }

  // Authentication logic
  const needsAuth = [
    'tree',
    'enrich',
    'backup',
    'diff',
    'check',
    'verify',
    'restore',
    'activate',
  ].includes(command);
  const canUseAuth = command === 'plan';

  let client: AdtClient | undefined;

  if (needsAuth || (canUseAuth && (envPath || destination))) {
    if (needsAuth && !envPath && !destination) {
      throw new Error(
        `Command "${command}" requires a TARGET system. Provide --target, --env or --env-path.`,
      );
    }

    if (envPath || destination) {
      logVerbose(1, `Connecting to system: ${destination || envPath}...`);

      const sapAuth = await getSapConfigFromBroker({
        destination,
        envPath,
        authRoot:
          typeof args['auth-root'] === 'string' ? args['auth-root'] : undefined,
        browserAuthPort:
          typeof args['browser-auth-port'] === 'string'
            ? Number.parseInt(args['browser-auth-port'], 10)
            : 10001,
        logger,
      });

      const allowAdtLogs =
        verbosityState.level >= 3 || Boolean(args['debug-adt']);
      const allowConnectionLogs =
        verbosityState.level >= 3 || Boolean(args['debug-adt']);
      const connectionLogger =
        allowConnectionLogs && shouldEnableConnectionLogger()
          ? logger
          : undefined;
      const adtLogger =
        command !== 'verify' &&
        command !== 'restore' &&
        allowAdtLogs &&
        shouldEnableAdtLogger()
          ? logger
          : undefined;

      const connection = createAbapConnection(
        sapAuth.config,
        connectionLogger,
        undefined,
        sapAuth.tokenRefresher,
      );
      // Resolve masterSystem/responsible for AdtClient:
      // Cloud (BTP): both from getSystemInformation endpoint
      // On-premise: responsible from connection username, no masterSystem
      const systemInfo = await getSystemInformation(connection);
      const masterSystem = systemInfo?.systemID;
      const responsible = systemInfo?.userName || sapAuth.config.username;

      client = new AdtClient(connection, adtLogger, {
        masterSystem,
        responsible,
      });
    }
  }

  if (command === 'tree') {
    if (!client) throw new Error('Client required');
    const packageName =
      typeof args.package === 'string' ? args.package : undefined;
    if (!packageName) throw new Error('Missing --package');
    const output = typeof args.output === 'string' ? args.output : 'tree.yaml';

    logVerbose(1, `Fetching package hierarchy for ${packageName}`);
    const hierarchy = await client
      .getUtils()
      .getPackageHierarchy(packageName.toUpperCase());
    const rootTree: BackupTreeNode = { ...hierarchy, restoreStatus: 'ok' };
    const enrichedRoot = await enrichTreeNode(rootTree, client, false);
    await collectTreeDependencies(client, enrichedRoot);

    const payload: BackupTreeFile = {
      schemaVersion: 2,
      generatedAt: new Date().toISOString(),
      package: packageName.toUpperCase(),
      root: enrichedRoot,
    };
    payload.checksum = computeBackupChecksum(payload);
    fs.writeFileSync(output, YAML.stringify(payload, { lineWidth: 0 }), 'utf8');
    console.log(`Tree written to ${output}`);
    console.log(
      `Next step: adt-backup enrich --input ${output} --output backup.yaml --target ${destination || '<sys>'}`,
    );
    return;
  }

  if (command === 'backup') {
    if (!client) throw new Error('Client required');
    const packageName =
      typeof args.package === 'string' ? args.package : undefined;
    const rawObjects = args.objects;
    const output =
      typeof args.output === 'string' ? args.output : 'backup.yaml';

    if (packageName) {
      const tree = await buildPackageBackupTree(client, packageName);
      updateTreeChecksums(tree.root);
      tree.checksum = computeBackupChecksum(tree);
      fs.writeFileSync(output, YAML.stringify(tree, { lineWidth: 0 }), 'utf8');
      console.log(`Backup written to ${output}`);
      console.log(
        `Next step: adt-backup plan --input ${output} --output plan.yaml`,
      );
      return;
    }

    if (typeof rawObjects !== 'string')
      throw new Error('Missing --objects or --package');
    const specs = rawObjects
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
      .map(parseObjectSpec);
    const objects: BackupObject[] = [];
    for (const spec of specs) {
      objects.push(await backupObject(client, spec));
    }
    const payload: BackupFile = {
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      objects,
    };
    payload.checksum = computeBackupChecksum(payload);
    fs.writeFileSync(output, YAML.stringify(payload, { lineWidth: 0 }), 'utf8');
    console.log(`Backup written to ${output}`);
    return;
  }

  if (command === 'enrich') {
    if (!client) throw new Error('Client required');
    const input = args.input;
    if (typeof input !== 'string') throw new Error('Missing --input');
    const output = typeof args.output === 'string' ? args.output : input;

    const backup = YAML.parse(fs.readFileSync(input, 'utf8')) as BackupTreeFile;
    backup.root = await enrichTreeNode(backup.root, client, true);
    updateTreeChecksums(backup.root);
    backup.checksum = computeBackupChecksum(backup);
    fs.writeFileSync(output, YAML.stringify(backup, { lineWidth: 0 }), 'utf8');
    console.log(`Enriched backup written to ${output}`);
    console.log(
      `Next step: adt-backup plan --input ${output} --output plan.yaml`,
    );
    return;
  }

  if (command === 'plan') {
    const input = args.input;
    if (typeof input !== 'string') throw new Error('Missing --input');
    const output = typeof args.output === 'string' ? args.output : 'plan.yaml';
    const mode = (args.mode as RestoreMode) || 'create';

    logVerbose(1, `Planning restoration from ${input} (offline)...`);
    const backup = YAML.parse(fs.readFileSync(input, 'utf8')) as BackupTreeFile;
    if (!backup || backup.schemaVersion !== 2)
      throw new Error('SchemaVersion 2 required');

    const allNodes = flattenTree(backup.root).filter(
      (n: BackupTreeNode) => n.type && n.restoreStatus === 'ok',
    );
    const packageNodes = allNodes.filter(
      (n: BackupTreeNode) => n.type === 'package',
    );
    const nonPackageNodes = allNodes.filter(
      (n: BackupTreeNode) => n.type !== 'package',
    );
    const groups = analyzeDependencies(nonPackageNodes);

    const plan: RestorePlan = {
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      backupFile: path.resolve(input),
      targetPackage: backup.package,
      groups: [
        {
          id: 0,
          isCircular: false,
          actions: packageNodes.map((node: BackupTreeNode) => ({
            id: getNodeObjectId(node)!,
            type: node.type!,
            name: node.name,
            action: mode as any,
            adtType: node.adtType,
          })),
        },
        ...groups.map((group, idx) => ({
          id: idx + 1,
          isCircular: group.isCircular,
          actions: group.nodes.map((node: BackupTreeNode) => ({
            id: getNodeObjectId(node)!,
            type: node.type!,
            name: node.name,
            functionGroupName: node.functionGroupName,
            action: mode as any,
            adtType: node.adtType,
          })),
        })),
      ],
    };

    fs.writeFileSync(output, YAML.stringify(plan, { lineWidth: 0 }), 'utf8');
    console.log(`Plan written to ${output}`);
    console.log(
      `Next step: adt-backup verify --plan ${output} --target ${destination || '<sys>'}`,
    );
    return;
  }

  if (command === 'verify') {
    if (!client) throw new Error('Client required');
    const planPath = args.plan;
    if (!planPath || typeof planPath !== 'string')
      throw new Error('Missing --plan');
    const output = typeof args.output === 'string' ? args.output : planPath;

    const plan = YAML.parse(fs.readFileSync(planPath, 'utf8')) as RestorePlan;
    const backup = YAML.parse(
      fs.readFileSync(plan.backupFile, 'utf8'),
    ) as BackupTreeFile;

    const verifyResult = await verifyBackup(client, backup, {
      mode: 'pre-restore',
    });
    const systemState = new Map<string, string>();
    for (const entry of verifyResult.entries) {
      systemState.set(`${entry.type}:${entry.name}`, entry.status);
    }

    const skipExisting = Boolean(args['skip-existing']);
    const skipUnchanged = Boolean(args['skip-unchanged']);

    for (const group of plan.groups) {
      for (const action of group.actions) {
        const id = `${action.type}:${action.name}`;
        const status = systemState.get(id);
        if (status === 'ok') {
          action.action = skipExisting || skipUnchanged ? 'skip' : 'update';
        } else if (
          status === 'package-mismatch' ||
          status === 'source-mismatch'
        ) {
          action.action = skipExisting ? 'skip' : 'update';
        } else {
          action.action = 'create';
        }
      }
    }

    fs.writeFileSync(output, YAML.stringify(plan, { lineWidth: 0 }), 'utf8');
    const skipActions = plan.groups
      .flatMap((g) => g.actions)
      .filter((a) => a.action === 'skip');
    const skipCount = skipActions.length;
    const skipIdSet = new Set(skipActions.map((a) => `${a.type}:${a.name}`));
    if (skipExisting && skipCount > 0) {
      verifyResult.summary.skip = skipCount;
      verifyResult.summary.update =
        (verifyResult.summary.update ?? 0) - skipCount;
    }
    console.log(
      formatVerifyResultsText(
        verifyResult.entries,
        verifyResult.summary,
        'pre-restore',
        verbosityState.level,
        skipIdSet.size > 0 ? skipIdSet : undefined,
      ),
    );
    if (skipCount > 0) {
      console.log(`  (${skipCount} existing objects will be skipped)`);
    }
    console.log(`Plan updated and saved to ${output}`);
    console.log(
      `Next step: adt-backup restore --plan ${output} --target ${destination || '<sys>'}`,
    );
    return;
  }

  if (command === 'restore') {
    if (!client) throw new Error('Client required');
    const planPath = args.plan;
    if (!planPath || typeof planPath !== 'string')
      throw new Error('Missing --plan');

    const plan = YAML.parse(fs.readFileSync(planPath, 'utf8')) as RestorePlan;
    const backup = YAML.parse(
      fs.readFileSync(plan.backupFile, 'utf8'),
    ) as BackupTreeFile;
    const allNodes = flattenTree(backup.root);
    const _nodeMap = new Map(allNodes.map((n) => [getNodeObjectId(n)!, n]));
    const _backupPackageNames = new Set(
      allNodes.filter((n) => n.type === 'package').map((n) => n.name),
    );

    const noActivate = Boolean(args['no-activate']);
    const activate =
      !noActivate && (Boolean(args.activate) || !args['no-activate-on-update']);
    const activateOnCreate = !noActivate && !args['no-activate-on-create'];
    const superPackage =
      typeof args['super-package'] === 'string'
        ? args['super-package']
        : undefined;
    const transportLayer =
      typeof args['transport-layer'] === 'string'
        ? args['transport-layer']
        : undefined;

    await restoreTreeBackup(
      client,
      backup.root,
      'upsert',
      activate,
      typeof args.transport === 'string' ? args.transport : undefined,
      undefined,
      new Map(
        plan.groups
          .flatMap((g) => g.actions)
          .map((a) => [a.id, a.action as any]),
      ),
      activateOnCreate,
      typeof args['software-component'] === 'string'
        ? args['software-component']
        : undefined,
      superPackage,
      transportLayer,
    );

    console.log(
      'Restore completed. Running post-restore check on TARGET system...',
    );
    const postResult = await verifyBackup(client, backup, {
      mode: 'post-restore',
    });
    console.log(
      formatVerifyResultsText(
        postResult.entries,
        postResult.summary,
        'post-restore',
        verbosityState.level,
      ),
    );
    return;
  }

  if (command === 'activate') {
    if (!client) throw new Error('Client required');
    const planPath = args.plan;
    if (!planPath || typeof planPath !== 'string')
      throw new Error('Missing --plan');

    const filter = typeof args.filter === 'string' ? args.filter : 'all';
    if (!['skip', 'update', 'all'].includes(filter)) {
      throw new Error(
        `Invalid --filter value: "${filter}". Must be skip, update, or all.`,
      );
    }

    const plan = YAML.parse(fs.readFileSync(planPath, 'utf8')) as RestorePlan;
    const allActions = plan.groups.flatMap((g) => g.actions);

    const filtered = allActions.filter((a) => {
      if (a.type === 'package') return false;
      if (!a.adtType) return false;
      if (filter === 'all') return a.action !== 'create';
      return a.action === filter;
    });

    if (filtered.length === 0) {
      console.log('No objects to activate.');
      return;
    }

    console.log(
      `Activating ${filtered.length} object(s) (filter: ${filter})...`,
    );

    // Group by plan groups to respect dependency order
    let activated = 0;
    let skipped = 0;
    let failed = 0;

    for (const group of plan.groups) {
      const groupRefs: ObjectReference[] = [];
      for (const action of group.actions) {
        if (action.type === 'package' || !action.adtType) continue;
        if (filter !== 'all' && action.action !== filter) continue;
        if (filter === 'all' && action.action === 'create') continue;
        groupRefs.push({ name: action.name, type: action.adtType });
      }

      if (groupRefs.length === 0) continue;

      logVerbose(
        2,
        `  [GROUP ${group.id}] Activating ${groupRefs.length} object(s)...`,
      );

      try {
        await client.getUtils().activateObjectsGroup(groupRefs, true);
        activated += groupRefs.length;
        for (const ref of groupRefs) {
          logVerbose(2, `    OK ${ref.type} ${ref.name}`);
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        failed += groupRefs.length;
        logVerbose(1, `  [!] Group ${group.id} activation failed: ${message}`);
      }
    }

    skipped = allActions.length - activated - failed;
    console.log(
      `Activation complete: ${activated} activated, ${skipped} skipped, ${failed} failed`,
    );
    return;
  }

  if (command === 'diff') {
    if (!client) throw new Error('Client required');
    const input = args.input;
    const objectSpec = args.object;
    const diffAll = Boolean(args.all);
    const _showOk = Boolean(args['show-ok']);
    const objectSpecValue = typeof objectSpec === 'string' ? objectSpec : '';
    if (typeof input !== 'string') throw new Error('Missing --input');
    if (!diffAll && typeof objectSpec !== 'string')
      throw new Error('Missing --object');

    const raw = fs.readFileSync(input, 'utf8');
    const parsed = YAML.parse(raw) as BackupFile | BackupTreeFile;
    verifyBackupChecksum(parsed);

    const diffMetadata = async (
      label: string,
      backupText: string,
      metadataXml: string,
      showNoDiff: boolean,
    ) => {
      const beforeMeta = extractMetadata(backupText);
      const afterMeta = extractMetadata(metadataXml);
      if (beforeMeta.packageName === afterMeta.packageName) {
        if (showNoDiff) console.log(`=== ${label}\nNo differences`);
        return false;
      }
      console.log(
        `=== ${label}\nchanged packageName: "${beforeMeta.packageName ?? ''}" -> "${afterMeta.packageName ?? ''}"`,
      );
      return true;
    };

    const diffSource = async (
      label: string,
      backupText: string,
      actualSource: string,
      showNoDiff: boolean,
    ) => {
      const unified = diffUnified(backupText, actualSource);
      if (!unified.trim()) {
        if (showNoDiff) console.log(`=== ${label}\nNo differences`);
        return false;
      }
      console.log(`=== ${label}\n${unified}`);
      return true;
    };

    if (parsed.schemaVersion === 2) {
      verifyTreeChecksums(parsed.root);
      if (!diffAll) {
        const spec = parseObjectSpec(objectSpecValue);
        const node = findNodeInTree(parsed.root, spec);
        if (!node || !node.codeBase64) throw new Error('Object not found');
        const backupText = decodeBase64(node.codeBase64);
        if (node.codeFormat === 'xml') {
          const metadataXml = await readMetadataXmlForType(
            client,
            node.type!,
            node.name,
            node.functionGroupName,
          );
          if (metadataXml)
            await diffMetadata(
              formatObjectSpec(spec),
              backupText,
              metadataXml,
              true,
            );
        } else {
          const actualSource = await readSourceText(client, spec);
          await diffSource(
            formatObjectSpec(spec),
            backupText,
            actualSource ?? '',
            true,
          );
        }
        return;
      }
    }
    return;
  }

  if (command === 'validate') {
    const input = args.input;
    if (typeof input !== 'string') throw new Error('Missing --input');
    const parsed = YAML.parse(fs.readFileSync(input, 'utf8')) as
      | BackupFile
      | BackupTreeFile;
    verifyBackupChecksum(parsed);
    if (parsed.schemaVersion === 2) verifyTreeChecksums(parsed.root);
    console.log('Backup validated');
    return;
  }

  if (command === 'extract') {
    const input = args.input;
    const objectSpec = args.object;
    const output = args.out;
    if (
      typeof input !== 'string' ||
      typeof objectSpec !== 'string' ||
      typeof output !== 'string'
    )
      throw new Error('Missing args');
    const parsed = YAML.parse(fs.readFileSync(input, 'utf8')) as BackupTreeFile;
    const spec = parseObjectSpec(objectSpec);
    const node = findNodeInTree(parsed.root, spec);
    if (!node || !node.codeBase64) throw new Error('Not found');
    fs.writeFileSync(output, decodeBase64(node.codeBase64), 'utf8');
    console.log(`Extracted to ${output}`);
    return;
  }

  if (command === 'patch') {
    const input = args.input;
    const objectSpec = args.object;
    const filePath = args.file;
    if (
      typeof input !== 'string' ||
      typeof objectSpec !== 'string' ||
      typeof filePath !== 'string'
    )
      throw new Error('Missing args');
    const output = typeof args.output === 'string' ? args.output : input;
    const parsed = YAML.parse(fs.readFileSync(input, 'utf8')) as BackupTreeFile;
    const node = findNodeInTree(parsed.root, parseObjectSpec(objectSpec));
    if (!node) throw new Error('Not found');
    node.codeBase64 = encodeBase64(fs.readFileSync(filePath, 'utf8'));
    node.codeChecksum = computeCodeChecksum(node.codeBase64);
    updateTreeChecksums(parsed.root);
    parsed.checksum = computeBackupChecksum(parsed);
    fs.writeFileSync(
      output as string,
      YAML.stringify(parsed, { lineWidth: 0 }),
      'utf8',
    );
    console.log(`Backup updated`);
    return;
  }

  if (command === 'check') {
    if (!client) throw new Error('Client required');
    const input = args.input;
    if (typeof input !== 'string') throw new Error('Missing --input');
    const backup = YAML.parse(fs.readFileSync(input, 'utf8')) as
      | BackupFile
      | BackupTreeFile;
    const result = await verifyBackup(client, backup, {
      strict: Boolean(args.strict),
    });
    console.log(
      formatVerifyResultsText(
        result.entries,
        result.summary,
        'pre-restore',
        verbosityState.level,
      ),
    );
    return;
  }

  throw new Error(`Unknown command: ${command}`);
}

function enableLogFile(logFile: string): void {
  const dir = path.dirname(logFile);
  if (dir && dir !== '.') fs.mkdirSync(dir, { recursive: true });
  const stream = fs.createWriteStream(logFile, { flags: 'a' });
  const wrap =
    (fn: any) =>
    (...args: any[]) => {
      fn(...args);
      stream.write(
        `${args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ')}\n`,
      );
    };
  console.log = wrap(console.log.bind(console));
  console.error = wrap(console.error.bind(console));
}
