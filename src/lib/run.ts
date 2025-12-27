import * as fs from 'node:fs';
import { AdtClient } from '@mcp-abap-adt/adt-clients';
import { createAbapConnection } from '@mcp-abap-adt/connection';
import YAML from 'yaml';
import { getSapConfigFromBroker } from './auth/getSapConfigFromBroker';
import { backupObject } from './backup/backupObject';
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
import { restoreObjects } from './restore/restoreObjects';
import { restoreTreeBackup } from './restore/restoreTreeBackup';
import { verbosityState } from './state/verbosity';
import { buildPackageBackupTree } from './tree/buildPackageBackupTree';
import { buildTreeList } from './tree/buildTreeList';
import { collectTreeObjects } from './tree/collectTreeObjects';
import { findNodeInTree } from './tree/findNodeInTree';
import { formatTreeListText } from './tree/formatTreeListText';
import { stripCodeFromTree } from './tree/stripCodeFromTree';
import type {
  BackupFile,
  BackupObject,
  BackupTreeFile,
  ObjectSpec,
  RestoreMode,
} from './types';
import { formatObjectSpec } from './utils/formatObjectSpec';
import { parseObjectSpec } from './utils/parseObjectSpec';

export async function run(): Promise<void> {
  const argv = process.argv.slice(2);
  verbosityState.level = getVerbosity(argv);
  applyLogEnv(verbosityState.level);
  const logger = createLogger(verbosityState.level);
  const command = argv[0];
  const args = parseArgs(argv.slice(1));

  if (!command || command === '--help' || command === '-h') {
    console.log(usage());
    process.exit(0);
  }

  if (command === 'extract') {
    const input = args.input;
    const objectSpec = args.object;
    const output = args.out;
    if (typeof input !== 'string') {
      throw new Error('Missing --input');
    }
    if (typeof objectSpec !== 'string') {
      throw new Error('Missing --object');
    }
    if (typeof output !== 'string') {
      throw new Error('Missing --out');
    }
    logVerbose(2, `Extracting ${objectSpec} from ${input}`);
    const raw = fs.readFileSync(input, 'utf8');
    const parsed = YAML.parse(raw) as BackupTreeFile;
    if (!parsed || parsed.schemaVersion !== 2) {
      throw new Error('Extract supports only schemaVersion 2 backups');
    }
    verifyBackupChecksum(parsed);
    verifyTreeChecksums(parsed.root);
    const spec = parseObjectSpec(objectSpec);
    logVerbose(3, `Parsed object spec: ${spec.type}:${spec.name}`);
    const node = findNodeInTree(parsed.root, spec);
    if (!node || !node.codeBase64) {
      throw new Error('Object not found or no codeBase64 in backup');
    }
    fs.writeFileSync(output, decodeBase64(node.codeBase64), 'utf8');
    console.log(`Extracted to ${output}`);
    return;
  }

  if (command === 'list') {
    const input = args.input;
    if (typeof input !== 'string') {
      throw new Error('Missing --input');
    }
    const format = typeof args.format === 'string' ? args.format : 'text';
    const flat = Boolean(args.flat);
    const raw = fs.readFileSync(input, 'utf8');
    const parsed = YAML.parse(raw) as BackupFile | BackupTreeFile;
    if (!parsed || typeof parsed !== 'object') {
      throw new Error('Invalid backup file format');
    }

    if ((parsed as BackupTreeFile).schemaVersion === 2) {
      const tree = parsed as BackupTreeFile;
      if (flat) {
        const objects: ObjectSpec[] = [];
        collectTreeObjects(tree.root, objects);
        if (format === 'json') {
          console.log(JSON.stringify(objects, null, 2));
        } else {
          for (const spec of objects) {
            console.log(formatObjectSpec(spec));
          }
        }
        return;
      }
      if (format === 'json') {
        console.log(JSON.stringify(buildTreeList(tree.root), null, 2));
      } else {
        const lines = formatTreeListText(tree.root);
        console.log(lines.join('\n'));
      }
      return;
    }

    if ((parsed as BackupFile).schemaVersion === 1) {
      const flat = parsed as BackupFile;
      const objects = flat.objects.map((obj) => ({
        type: obj.type,
        name: obj.name,
        functionGroupName: obj.functionGroupName,
      }));
      if (format === 'json') {
        console.log(JSON.stringify(objects, null, 2));
      } else {
        for (const spec of objects) {
          console.log(formatObjectSpec(spec));
        }
      }
      return;
    }

    throw new Error('Invalid backup file format');
  }

  if (command === 'patch') {
    const input = args.input;
    const objectSpec = args.object;
    const filePath = args.file;
    if (typeof input !== 'string') {
      throw new Error('Missing --input');
    }
    if (typeof objectSpec !== 'string') {
      throw new Error('Missing --object');
    }
    if (typeof filePath !== 'string') {
      throw new Error('Missing --file');
    }
    const output = typeof args.output === 'string' ? args.output : input;
    logVerbose(2, `Patching ${objectSpec} in ${input}`);
    const raw = fs.readFileSync(input, 'utf8');
    const parsed = YAML.parse(raw) as BackupTreeFile;
    if (!parsed || parsed.schemaVersion !== 2) {
      throw new Error('Patch supports only schemaVersion 2 backups');
    }
    verifyBackupChecksum(parsed);
    verifyTreeChecksums(parsed.root);
    const spec = parseObjectSpec(objectSpec);
    logVerbose(3, `Parsed object spec: ${spec.type}:${spec.name}`);
    const node = findNodeInTree(parsed.root, spec);
    if (!node) {
      throw new Error('Object not found in backup');
    }
    const fileContent = fs.readFileSync(filePath, 'utf8');
    node.codeBase64 = encodeBase64(fileContent);
    node.codeChecksum = undefined;
    node.restoreStatus = 'ok';
    if (!node.codeFormat) {
      node.codeFormat = 'source';
    }
    updateTreeChecksums(parsed.root);
    parsed.checksum = computeBackupChecksum(parsed);
    const yamlText = YAML.stringify(parsed, { lineWidth: 0 });
    fs.writeFileSync(output as string, yamlText, 'utf8');
    console.log(`Backup updated at ${output}`);
    return;
  }

  if (command === 'validate') {
    const input = args.input;
    const objectSpec = args.object;
    if (typeof input !== 'string') {
      throw new Error('Missing --input');
    }
    const raw = fs.readFileSync(input, 'utf8');
    const parsed = YAML.parse(raw) as BackupFile | BackupTreeFile;
    if (!parsed || typeof parsed !== 'object') {
      throw new Error('Invalid backup file format');
    }

    verifyBackupChecksum(parsed);

    if ((parsed as BackupTreeFile).schemaVersion === 2) {
      const tree = parsed as BackupTreeFile;
      if (typeof objectSpec === 'string') {
        const spec = parseObjectSpec(objectSpec);
        const node = findNodeInTree(tree.root, spec);
        if (!node) {
          throw new Error(`Object not found: ${formatObjectSpec(spec)}`);
        }
        if (!node.codeBase64) {
          throw new Error('Object has no codeBase64 to validate');
        }
        if (!node.codeChecksum) {
          throw new Error('Object has no codeChecksum to validate');
        }
        const expected = computeCodeChecksum(node.codeBase64);
        if (expected !== node.codeChecksum) {
          throw new Error('Object code checksum mismatch');
        }
        console.log(`Validated object ${formatObjectSpec(spec)}`);
      } else {
        verifyTreeChecksums(tree.root);
        console.log('Backup validated');
      }
      return;
    }

    if ((parsed as BackupFile).schemaVersion === 1) {
      if (typeof objectSpec === 'string') {
        const spec = parseObjectSpec(objectSpec);
        const flat = parsed as BackupFile;
        const matches = flat.objects.some(
          (obj) =>
            obj.type === spec.type &&
            obj.name === spec.name &&
            (spec.functionGroupName
              ? obj.functionGroupName === spec.functionGroupName
              : true),
        );
        if (!matches) {
          throw new Error(`Object not found: ${formatObjectSpec(spec)}`);
        }
        console.log(`Validated object ${formatObjectSpec(spec)}`);
      } else {
        console.log('Backup validated');
      }
      return;
    }

    throw new Error('Invalid backup file format');
  }

  const envPath =
    typeof args.env === 'string'
      ? args.env
      : typeof args.config === 'string'
        ? args.config
        : undefined;
  const destination =
    typeof args.destination === 'string' ? args.destination : undefined;
  const authRoot =
    typeof args['auth-root'] === 'string' ? args['auth-root'] : undefined;
  if (!envPath && !destination) {
    throw new Error('Missing --destination (or provide --env)');
  }
  const { config, tokenRefresher } = await getSapConfigFromBroker({
    destination,
    envPath,
    authRoot,
    logger,
  });
  const connectionLogger = shouldEnableConnectionLogger() ? logger : undefined;
  const adtLogger = shouldEnableAdtLogger() ? logger : undefined;
  const connection = createAbapConnection(
    config,
    connectionLogger,
    undefined,
    tokenRefresher,
  );
  const client = new AdtClient(connection, adtLogger);

  if (command === 'backup') {
    const rawObjects = args.objects;
    const packageName =
      typeof args.package === 'string' ? args.package : undefined;

    if (packageName) {
      logVerbose(2, `Starting package backup for ${packageName}`);
      const output =
        typeof args.output === 'string' ? args.output : 'backup.yaml';
      const tree = await buildPackageBackupTree(client, packageName, true);
      updateTreeChecksums(tree.root);
      tree.checksum = computeBackupChecksum(tree);
      const yamlText = YAML.stringify(tree, { lineWidth: 0 });
      fs.writeFileSync(output, yamlText, 'utf8');
      console.log(`Backup written to ${output}`);
      return;
    }

    if (typeof rawObjects !== 'string') {
      throw new Error('Missing --objects or --package');
    }
    logVerbose(2, `Starting objects backup (${rawObjects})`);
    const specs = rawObjects
      .split(',')
      .map((spec) => spec.trim())
      .filter(Boolean)
      .map(parseObjectSpec);

    const objects: BackupObject[] = [];
    for (const spec of specs) {
      logVerbose(3, `Backup ${spec.type}:${spec.name}`);
      const backup = await backupObject(client, spec);
      objects.push(backup);
    }

    const output =
      typeof args.output === 'string' ? args.output : 'backup.yaml';
    const payload: BackupFile = {
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      objects,
    };
    payload.checksum = computeBackupChecksum(payload);
    const yamlText = YAML.stringify(payload, { lineWidth: 0 });
    fs.writeFileSync(output, yamlText, 'utf8');
    console.log(`Backup written to ${output}`);
    return;
  }

  if (command === 'tree') {
    const packageName =
      typeof args.package === 'string' ? args.package : undefined;
    if (!packageName) {
      throw new Error('Missing --package');
    }
    logVerbose(2, `Starting tree preview for ${packageName}`);
    const output = typeof args.output === 'string' ? args.output : 'tree.yaml';
    const tree = await buildPackageBackupTree(client, packageName, false);
    const lightTree: BackupTreeFile = {
      ...tree,
      root: stripCodeFromTree(tree.root),
    };
    lightTree.checksum = computeBackupChecksum(lightTree);
    const yamlText = YAML.stringify(lightTree, { lineWidth: 0 });
    fs.writeFileSync(output, yamlText, 'utf8');
    console.log(`Tree written to ${output}`);
    return;
  }

  if (command === 'restore') {
    const input = args.input;
    if (typeof input !== 'string') {
      throw new Error('Missing --input');
    }
    logVerbose(2, `Starting restore from ${input}`);
    const raw = fs.readFileSync(input, 'utf8');
    const mode = (args.mode as RestoreMode) || 'upsert';
    const activate = Boolean(args.activate);
    const parsed = YAML.parse(raw) as BackupFile | BackupTreeFile;
    if (!parsed || typeof parsed !== 'object') {
      throw new Error('Invalid backup file format');
    }
    if ((parsed as BackupTreeFile).schemaVersion === 2) {
      const tree = parsed as BackupTreeFile;
      verifyBackupChecksum(tree);
      verifyTreeChecksums(tree.root);
      logVerbose(2, `Restoring tree backup for package ${tree.package}`);
      await restoreTreeBackup(client, tree.root, mode, activate);
      console.log('Restore completed');
      return;
    }
    if (!Array.isArray((parsed as BackupFile).objects)) {
      throw new Error('Invalid backup file format');
    }
    const flat = parsed as BackupFile;
    verifyBackupChecksum(flat);
    logVerbose(2, `Restoring flat backup (${flat.objects.length} objects)`);
    await restoreObjects(client, flat.objects, mode, activate);
    console.log(`Restore completed for ${flat.objects.length} object(s)`);
    return;
  }

  throw new Error(`Unknown command: ${command}`);
}
