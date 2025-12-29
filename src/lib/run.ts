import * as fs from 'node:fs';
import * as path from 'node:path';
import { AdtClient } from '@mcp-abap-adt/adt-clients';
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
import { redactText, safeStringify } from './cli/redact';
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
import { buildRestorePlan } from './restore/buildRestorePlan';
import { deleteBackupObjects } from './restore/deleteBackupObjects';
import { restoreObjects } from './restore/restoreObjects';
import { restoreTreeBackup } from './restore/restoreTreeBackup';
import { verbosityState } from './state/verbosity';
import { buildPackageBackupTree } from './tree/buildPackageBackupTree';
import { buildTreeList } from './tree/buildTreeList';
import { collectTreeObjects } from './tree/collectTreeObjects';
import { findNodeInTree } from './tree/findNodeInTree';
import { formatTreeListText } from './tree/formatTreeListText';
import { getNodeObjectSpec } from './tree/getNodeObjectSpec';
import { stripCodeFromTree } from './tree/stripCodeFromTree';
import type {
  BackupFile,
  BackupObject,
  BackupTreeFile,
  BackupTreeNode,
  ObjectSpec,
  RestoreMode,
} from './types';
import { diffUnified } from './utils/diffUnified';
import { formatObjectSpec } from './utils/formatObjectSpec';
import { parseObjectSpec } from './utils/parseObjectSpec';
import { collectBackupNodes } from './verify/collectBackupNodes';
import { findOtherType } from './verify/findOtherType';
import { formatVerifyResultsText } from './verify/formatVerifyResultsText';
import { verifyBackup } from './verify/verifyBackup';
import { extractMetadata } from './xml/extractMetadata';

export async function run(): Promise<void> {
  const argv = process.argv.slice(2);
  verbosityState.level = getVerbosity(argv);
  const logger = createLogger(verbosityState.level);
  const command = argv[0];
  const args = parseArgs(argv.slice(1));
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
    const showDeps = Boolean(args.deps);
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
        console.log(
          JSON.stringify(buildTreeList(tree.root, { showDeps }), null, 2),
        );
      } else {
        const lines = formatTreeListText(tree.root, 0, { showDeps });
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
  const allowAdtLogs = verbosityState.level >= 2 || debugAdt;
  const allowConnectionLogs = verbosityState.level >= 3 || debugAdt;
  const connectionLogger =
    allowConnectionLogs && shouldEnableConnectionLogger() ? logger : undefined;
  const adtLogger =
    allowAdtLogs && shouldEnableAdtLogger() ? logger : undefined;
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

  if (command === 'diff') {
    const input = args.input;
    const objectSpec = args.object;
    const diffAll = Boolean(args.all);
    const showOk = Boolean(args['show-ok']);
    const objectSpecValue = typeof objectSpec === 'string' ? objectSpec : '';
    if (typeof input !== 'string') {
      throw new Error('Missing --input');
    }
    if (!diffAll && typeof objectSpec !== 'string') {
      throw new Error('Missing --object (or use --all)');
    }
    const raw = fs.readFileSync(input, 'utf8');
    const parsed = YAML.parse(raw) as BackupFile | BackupTreeFile;
    if (!parsed || typeof parsed !== 'object') {
      throw new Error('Invalid backup file format');
    }
    verifyBackupChecksum(parsed);
    const diffMetadata = async (
      label: string,
      backupText: string,
      metadataXml: string,
      showNoDiff: boolean,
    ): Promise<boolean> => {
      const beforeMeta = extractMetadata(backupText);
      const afterMeta = extractMetadata(metadataXml);
      const changes: Array<{ key: string; before?: string; after?: string }> =
        [];
      if (beforeMeta.packageName !== afterMeta.packageName) {
        changes.push({
          key: 'packageName',
          before: beforeMeta.packageName,
          after: afterMeta.packageName,
        });
      }
      if (changes.length === 0) {
        if (showNoDiff) {
          console.log(`=== ${label}`);
          console.log('No differences');
        }
        return false;
      }
      console.log(`=== ${label}`);
      for (const change of changes) {
        console.log(
          `changed ${change.key}: "${change.before ?? ''}" -> "${change.after ?? ''}"`,
        );
      }
      return true;
    };

    const diffSource = async (
      label: string,
      backupText: string,
      actualSource: string,
      showNoDiff: boolean,
    ): Promise<boolean> => {
      const unified = diffUnified(backupText, actualSource);
      if (!unified.trim()) {
        if (showNoDiff) {
          console.log(`=== ${label}`);
          console.log('No differences');
        }
        return false;
      }
      console.log(`=== ${label}`);
      console.log(unified);
      return true;
    };

    let hasAnyDiff = false;

    if ((parsed as BackupTreeFile).schemaVersion === 2) {
      const tree = parsed as BackupTreeFile;
      verifyTreeChecksums(tree.root);
      if (!diffAll) {
        const spec = parseObjectSpec(objectSpecValue);
        const node = findNodeInTree(tree.root, spec);
        if (!node || !node.type) {
          throw new Error(`Object not found: ${formatObjectSpec(spec)}`);
        }
        if (!node.codeBase64) {
          throw new Error('Object has no payload to diff');
        }
        const label = formatObjectSpec(spec);
        const backupText = decodeBase64(node.codeBase64);
        if (node.codeFormat === 'xml') {
          try {
            const metadataXml = await readMetadataXmlForType(
              client,
              node.type,
              node.name,
              node.functionGroupName,
            );
            if (!metadataXml) {
              throw new Error('Metadata not available for diff');
            }
            const hasDiff = await diffMetadata(
              label,
              backupText,
              metadataXml,
              true,
            );
            if (!hasDiff) {
              console.log('No metadata differences detected');
            }
            return;
          } catch (_error) {
            const otherType = await findOtherType(client, node.type, node.name);
            if (otherType && otherType !== node.type) {
              console.log(`=== ${label}`);
              console.log(`changed type: "${node.type}" -> "${otherType}"`);
              return;
            }
            throw _error;
          }
        }
        const actualSource = await readSourceText(client, {
          type: node.type,
          name: node.name,
          functionGroupName: node.functionGroupName,
        });
        if (actualSource === undefined) {
          throw new Error('Source not available for diff');
        }
        const hasDiff = await diffSource(label, backupText, actualSource, true);
        if (!hasDiff) {
          console.log('No source differences detected');
        }
        return;
      }

      const nodes: BackupTreeNode[] = [];
      collectBackupNodes(tree.root, nodes);
      for (const node of nodes) {
        if (!node.type || !node.codeBase64) {
          continue;
        }
        const spec = {
          type: node.type,
          name: node.name,
          functionGroupName: node.functionGroupName,
        } satisfies ObjectSpec;
        const label = formatObjectSpec(spec);
        const backupText = decodeBase64(node.codeBase64);
        if (node.codeFormat === 'xml') {
          try {
            const metadataXml = await readMetadataXmlForType(
              client,
              node.type,
              node.name,
              node.functionGroupName,
            );
            if (!metadataXml) {
              continue;
            }
            const hasDiff = await diffMetadata(
              label,
              backupText,
              metadataXml,
              showOk,
            );
            if (hasDiff) {
              hasAnyDiff = true;
            }
            continue;
          } catch (_error) {
            const otherType = await findOtherType(client, node.type, node.name);
            if (otherType && otherType !== node.type) {
              console.log(`=== ${label}`);
              console.log(`changed type: "${node.type}" -> "${otherType}"`);
              hasAnyDiff = true;
            }
            continue;
          }
        }
        const actualSource = await readSourceText(client, spec);
        if (actualSource === undefined) {
          continue;
        }
        const hasDiff = await diffSource(
          label,
          backupText,
          actualSource,
          showOk,
        );
        if (hasDiff) {
          hasAnyDiff = true;
        }
      }
      if (!hasAnyDiff) {
        console.log('No differences detected');
      }
      return;
    }

    const flat = parsed as BackupFile;
    if (!Array.isArray(flat.objects)) {
      throw new Error('Invalid backup file format');
    }
    if (!diffAll) {
      const spec = parseObjectSpec(objectSpecValue);
      const obj = flat.objects.find(
        (item) =>
          item.type === spec.type &&
          item.name === spec.name &&
          (spec.functionGroupName
            ? item.functionGroupName === spec.functionGroupName
            : true),
      );
      if (!obj) {
        throw new Error(`Object not found: ${formatObjectSpec(spec)}`);
      }
      if (!obj.source) {
        throw new Error('Object has no payload to diff');
      }
      const actualSource = await readSourceText(client, spec);
      if (actualSource === undefined) {
        throw new Error('Source not available for diff');
      }
      const hasDiff = await diffSource(
        formatObjectSpec(spec),
        obj.source,
        actualSource,
        true,
      );
      if (!hasDiff) {
        console.log('No source differences detected');
      }
      return;
    }
    for (const obj of flat.objects) {
      if (!obj.source) {
        continue;
      }
      const spec = {
        type: obj.type,
        name: obj.name,
        functionGroupName: obj.functionGroupName,
      } satisfies ObjectSpec;
      const actualSource = await readSourceText(client, spec);
      if (actualSource === undefined) {
        continue;
      }
      const hasDiff = await diffSource(
        formatObjectSpec(spec),
        obj.source,
        actualSource,
        showOk,
      );
      if (hasDiff) {
        hasAnyDiff = true;
      }
    }
    if (!hasAnyDiff) {
      console.log('No differences detected');
    }
    return;
  }

  if (command === 'verify') {
    const input = args.input;
    if (typeof input !== 'string') {
      throw new Error('Missing --input');
    }
    const format = typeof args.format === 'string' ? args.format : 'text';
    const strict = Boolean(args.strict);
    const raw = fs.readFileSync(input, 'utf8');
    const parsed = YAML.parse(raw) as BackupFile | BackupTreeFile;
    if (!parsed || typeof parsed !== 'object') {
      throw new Error('Invalid backup file format');
    }
    verifyBackupChecksum(parsed);
    if ((parsed as BackupTreeFile).schemaVersion === 2) {
      verifyTreeChecksums((parsed as BackupTreeFile).root);
    }
    const result = await verifyBackup(client, parsed, { strict });
    if (format === 'json') {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(formatVerifyResultsText(result.entries, result.summary));
    }
    if (result.summary.conflicts > 0) {
      throw new Error(`Conflicts found: ${result.summary.conflicts}`);
    }
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
    const activateOnUpdate =
      Boolean(args.activate) || !args['no-activate-on-update'];
    const parsed = YAML.parse(raw) as BackupFile | BackupTreeFile;
    if (!parsed || typeof parsed !== 'object') {
      throw new Error('Invalid backup file format');
    }
    const force = Boolean(args.force);
    const strict = Boolean(args.strict);
    const dangerous = Boolean(args.dangerous);
    const activateOnCreate = !args['no-activate-on-create'];
    const transportRequest =
      typeof args.transport === 'string' ? args.transport : undefined;
    if (transportRequest) {
      logVerbose(1, `Using transport request for restore: ${transportRequest}`);
    }
    if ((parsed as BackupTreeFile).schemaVersion === 2) {
      const tree = parsed as BackupTreeFile;
      verifyBackupChecksum(tree);
      verifyTreeChecksums(tree.root);
      if (dangerous) {
        logVerbose(
          1,
          `Dangerous mode: deleting ${tree.package} objects from backup before restore`,
        );
        await deleteBackupObjects(client, tree, transportRequest);
      }
      if (!force) {
        const result = await verifyBackup(client, tree, { strict });
        if (result.summary.conflicts > 0) {
          throw new Error(
            `Conflicts found: ${result.summary.conflicts}. Use --force to restore anyway.`,
          );
        }
        const plan = buildRestorePlan(tree.root, result.entries);
        const summary = plan.reduce(
          (acc, item) => {
            acc[item.action] = (acc[item.action] || 0) + 1;
            return acc;
          },
          {} as Record<string, number>,
        );
        logVerbose(
          1,
          `Restore plan: create ${summary.create || 0}, update ${summary.update || 0}, skip ${summary.skip || 0}, error ${summary.error || 0}`,
        );
        for (const item of plan) {
          if (item.action === 'skip') {
            continue;
          }
          const spec = getNodeObjectSpec(item.node);
          const label = spec ? formatObjectSpec(spec) : item.node.name;
          logVerbose(2, `Plan ${item.action}: ${label} (${item.status})`);
        }
        const restoreIds = new Set(
          plan
            .filter(
              (item) => item.action === 'create' || item.action === 'update',
            )
            .map((item) => item.id),
        );
        const restoreActions = new Map<string, RestoreMode>();
        for (const item of plan) {
          if (item.action === 'create') {
            restoreActions.set(item.id, 'create');
          } else if (item.action === 'update') {
            restoreActions.set(item.id, 'update');
          }
        }
        if (restoreIds.size === 0) {
          console.log('Restore skipped: no changes detected');
          return;
        }
        logVerbose(2, `Restoring tree backup for package ${tree.package}`);
        await restoreTreeBackup(
          client,
          tree.root,
          mode,
          activateOnUpdate,
          transportRequest,
          restoreIds,
          restoreActions,
          activateOnCreate,
        );
        console.log('Restore completed');
        return;
      }
      logVerbose(2, `Restoring tree backup for package ${tree.package}`);
      await restoreTreeBackup(
        client,
        tree.root,
        mode,
        activateOnUpdate,
        transportRequest,
        undefined,
        undefined,
        activateOnCreate,
      );
      console.log('Restore completed');
      return;
    }
    if (!Array.isArray((parsed as BackupFile).objects)) {
      throw new Error('Invalid backup file format');
    }
    const flat = parsed as BackupFile;
    verifyBackupChecksum(flat);
    if (dangerous) {
      throw new Error('Dangerous mode is supported only for package backups');
    }
    if (!force) {
      const result = await verifyBackup(client, flat, { strict });
      if (result.summary.conflicts > 0) {
        throw new Error(
          `Conflicts found: ${result.summary.conflicts}. Use --force to restore anyway.`,
        );
      }
      const restoreActions = new Map<string, RestoreMode>();
      for (const entry of result.entries) {
        if (entry.status === 'missing') {
          restoreActions.set(`${entry.type}:${entry.name}`, 'create');
        } else if (
          entry.status === 'package-mismatch' ||
          entry.status === 'source-mismatch'
        ) {
          restoreActions.set(`${entry.type}:${entry.name}`, 'update');
        }
      }
      if (restoreActions.size === 0) {
        console.log('Restore skipped: no changes detected');
        return;
      }
      logVerbose(2, `Restoring flat backup (${flat.objects.length} objects)`);
      await restoreObjects(
        client,
        flat.objects,
        mode,
        activateOnUpdate,
        transportRequest,
        restoreActions,
        activateOnCreate,
      );
      console.log(`Restore completed for ${flat.objects.length} object(s)`);
      return;
    }
    logVerbose(2, `Restoring flat backup (${flat.objects.length} objects)`);
    await restoreObjects(
      client,
      flat.objects,
      mode,
      activateOnUpdate,
      transportRequest,
      undefined,
      activateOnCreate,
    );
    console.log(`Restore completed for ${flat.objects.length} object(s)`);
    return;
  }

  throw new Error(`Unknown command: ${command}`);
}

function enableLogFile(logFile: string): void {
  const dir = path.dirname(logFile);
  if (dir && dir !== '.') {
    fs.mkdirSync(dir, { recursive: true });
  }
  const stream = fs.createWriteStream(logFile, { flags: 'a' });

  const writeLine = (args: unknown[]): void => {
    const line = args.map(formatLogArg).join(' ');
    stream.write(`${line}\n`);
  };

  const wrap =
    (fn: (...args: unknown[]) => void) =>
    (...args: unknown[]): void => {
      fn(...args);
      writeLine(args);
    };

  console.log = wrap(console.log.bind(console));
  console.info = wrap(console.info.bind(console));
  console.warn = wrap(console.warn.bind(console));
  console.error = wrap(console.error.bind(console));
}

function formatLogArg(arg: unknown): string {
  if (arg instanceof Error) {
    return redactText(arg.stack ?? arg.message);
  }
  if (typeof arg === 'string') {
    return redactText(arg);
  }
  try {
    return safeStringify(arg);
  } catch {
    return String(arg);
  }
}
