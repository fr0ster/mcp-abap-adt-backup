import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import {
  analyseActivation,
  analyseException,
  analysePublication,
} from '@mcp-abap-adt/adt-strategies';
import {
  ADT_NO_FAILURE,
  type IAdtActivatable,
  type IAdtCreatable,
  type IAdtLockable,
  type IAdtMetadataUpdatable,
  type IAdtResponse,
  type IAdtUpdatable,
  type IAnalyse,
} from '@mcp-abap-adt/interfaces-adt';
import { AdtCallError, describeFailure, requireOk } from '../adt/answer';
import type { RestoreTarget } from '../adt/RestoreTarget';
import { logVerbose } from '../cli/logVerbose';
import { decodeBase64 } from '../crypto/decodeBase64';
import { restoreMessageClass } from '../messageClass/restoreMessageClass';
import type { ParsedMessageClass } from '../messageClass/types';
import type { BackupConfig, BackupTreeNode, RestoreMode } from '../types';
import { booleanField, oneOf, stringField } from '../utils/configFields';
import { detectTransformationType } from '../utils/detectTransformationType';
import { ensureDescription } from '../utils/ensureDescription';
import { parseBdefSource } from '../utils/parseBdefSource';
import { parseBehaviorDefinitionFromClass } from '../utils/parseBehaviorDefinitionFromClass';
import { parsePackageConfig } from '../xml/parsePackageConfig';

export interface WriteObjectOptions {
  /** `update` writes an object that exists; anything else creates it first. */
  mode: RestoreMode;
  /** Activate the object on its own once written (else a group activation will). */
  activate: boolean;
  transportRequest?: string;
  softwareComponent?: string;
  /** Packages the backup restores itself, so a super package among them is kept. */
  backupPackageNames?: Set<string>;
  /** Super package for a package whose own is not in the backup. */
  superPackage?: string;
  transportLayer?: string;
}

/**
 * One object's write, as its steps.
 *
 * Each step is one ADT request. adt-clients composes none of them since 18.0.0
 * — no lock inside `update`, no activation inside `create` — so the order is
 * this CLI's, and it is written once, in {@link runSequence}.
 */
interface WriteSteps {
  create?: () => Promise<IAdtResponse<unknown>>;
  lock?: () => Promise<IAdtResponse<string>>;
  write?: (body: string, lockHandle: string) => Promise<IAdtResponse<unknown>>;
  unlock?: (lockHandle: string) => Promise<IAdtResponse<void>>;
  activate?: () => Promise<IAdtResponse<unknown>>;
}

type CreateConfig<C> = Omit<C, 'source'> & { source?: never };

/** A type whose content is its source: `update` writes `options.source`. */
type SourceHandler<C> = IAdtCreatable<C, unknown> &
  IAdtLockable<C> &
  IAdtUpdatable<Partial<C>, unknown> &
  IAdtActivatable<C, unknown>;

/** A type whose content is its document: `updateMetadata` writes it whole. */
type DocumentHandler<C> = IAdtCreatable<C, unknown> &
  IAdtLockable<C> &
  IAdtMetadataUpdatable<Partial<C>, unknown> &
  IAdtActivatable<C, unknown>;

// The error strategy for every step but the activation: a refusal SAP writes
// as `exc:exception` — inside a 2xx or not — is a failure with SAP's text.
const refused = { analyse: analyseException };

function sourceSteps<C>(
  handler: SourceHandler<C>,
  id: Partial<C>,
  create?: CreateConfig<C>,
): WriteSteps {
  return {
    create: create ? () => handler.create(create, refused) : undefined,
    lock: () => handler.lock(id, refused),
    write: (source, lockHandle) =>
      handler.update(id, { source, lockHandle, ...refused }),
    unlock: (lockHandle) => handler.unlock(id, lockHandle, refused),
    activate: () => handler.activate(id, { analyse: analyseActivation }),
  };
}

function documentSteps<C>(
  handler: DocumentHandler<C>,
  id: Partial<C>,
  create?: CreateConfig<C>,
): WriteSteps {
  return {
    create: create ? () => handler.create(create, refused) : undefined,
    lock: () => handler.lock(id, refused),
    // The backed-up document, whole: an update is a replace, and a document
    // this CLI assembled from parsed fields would drop what it did not parse.
    write: (source, lockHandle) =>
      handler.updateMetadata(id, { source, lockHandle, ...refused }),
    unlock: (lockHandle) => handler.unlock(id, lockHandle, refused),
    activate: () => handler.activate(id, { analyse: analyseActivation }),
  };
}

/**
 * create → lock → write → unlock → activate, each step judged on its own.
 *
 * The unlock runs on every path out of a taken lock. A failed write is the
 * error that is reported; an unlock that fails after it is logged beside it,
 * since the lock it leaves behind is what the user will meet next.
 */
async function runSequence(
  label: string,
  steps: WriteSteps,
  body: string | undefined,
  options: WriteObjectOptions,
): Promise<void> {
  if (options.mode !== 'update' && steps.create) {
    logVerbose(3, `    create ${label}`);
    requireOk(await steps.create(), `create ${label}`);
  }

  if (body !== undefined && steps.write && steps.lock && steps.unlock) {
    logVerbose(3, `    lock ${label}`);
    const lockHandle = requireOk(await steps.lock(), `lock ${label}`);
    if (!lockHandle) {
      throw new Error(
        `lock ${label}: SAP answered without a lock handle, so there is nothing to write under`,
      );
    }
    let writeError: unknown;
    try {
      logVerbose(3, `    write ${label}`);
      requireOk(await steps.write(body, lockHandle), `write ${label}`);
    } catch (error) {
      writeError = error;
    }
    logVerbose(3, `    unlock ${label}`);
    const unlocked = await steps.unlock(lockHandle);
    if (writeError !== undefined) {
      if (!unlocked.ok) {
        logVerbose(
          1,
          `  [WARN] unlock ${label} failed after a failed write: ${describeFailure(unlocked.getError())}`,
        );
      }
      throw writeError;
    }
    requireOk(unlocked, `unlock ${label}`);
  }

  if (options.activate && steps.activate) {
    logVerbose(3, `    activate ${label}`);
    requireOk(await steps.activate(), `activate ${label}`);
  }
}

/**
 * Write one backed-up object to the target system.
 *
 * Replaces the two near-identical per-type chains the restore had (one for
 * flat backups, one for tree backups). Every type takes the same sequence;
 * what differs per type is only which handler, which create config and which
 * write — source or document.
 */
export async function writeObject(
  target: RestoreTarget,
  node: BackupTreeNode,
  options: WriteObjectOptions,
): Promise<void> {
  if (options.mode === 'skip') {
    logVerbose(2, `  [SKIP] ${node.type}:${node.name}`);
    return;
  }
  if (!node.type || node.restoreStatus !== 'ok') {
    return;
  }

  const { client } = target;
  const name = node.name;
  const label = `${node.type} ${name}`;
  const transportRequest = options.transportRequest?.trim() || undefined;
  const config = ensureDescription(configOf(node), name);
  const description = stringField(config, 'description') ?? name;
  const packageName = stringField(config, 'packageName');
  const payload = node.codeBase64 ? decodeBase64(node.codeBase64) : undefined;
  const create = options.mode !== 'update';

  switch (node.type) {
    case 'package':
      await writePackage(client, node, config, options);
      return;

    case 'messageClass': {
      if (!payload) {
        throw new Error(
          `messageClass ${name}: missing payload (cannot restore)`,
        );
      }
      const parsed = JSON.parse(payload) as ParsedMessageClass;
      await restoreMessageClass(target, parsed, {
        mode: options.mode,
        name,
        description: parsed.description ?? node.description,
        packageName: parsed.packageName ?? packageName,
        transportRequest,
      });
      return;
    }

    case 'serviceBinding': {
      await writeServiceBinding(client, name, config, {
        create,
        description,
        packageName,
        transportRequest,
      });
      return;
    }

    // Types that are their document.
    case 'domain': {
      const id = { domainName: name, transportRequest };
      await runSequence(
        label,
        documentSteps(
          client.getDomain(),
          id,
          create ? { ...id, packageName, description } : undefined,
        ),
        documentPayload(node, payload),
        options,
      );
      return;
    }
    case 'dataElement': {
      const id = { dataElementName: name, transportRequest };
      await runSequence(
        label,
        documentSteps(
          client.getDataElement(),
          id,
          create ? { ...id, packageName, description } : undefined,
        ),
        documentPayload(node, payload),
        options,
      );
      return;
    }
    case 'tableType': {
      // A table type is its document whatever format an older backup
      // recorded: the old source read fetched the same XML.
      const id = { tableTypeName: name, transportRequest };
      await runSequence(
        label,
        documentSteps(
          client.getTableType(),
          id,
          create ? { ...id, packageName, description } : undefined,
        ),
        payload,
        options,
      );
      return;
    }
    case 'functionGroup': {
      const id = { functionGroupName: name, transportRequest };
      await runSequence(
        label,
        documentSteps(
          client.getFunctionGroup(),
          id,
          create ? { ...id, packageName, description } : undefined,
        ),
        documentPayload(node, payload),
        options,
      );
      return;
    }

    // Types whose content is source.
    case 'class': {
      const id = { className: name, transportRequest };
      await runSequence(
        label,
        sourceSteps(
          client.getClass(),
          id,
          create
            ? {
                ...id,
                packageName,
                description,
                superclass: stringField(config, 'superclass'),
                final: booleanField(config, 'final'),
                abstract: booleanField(config, 'abstract'),
                createProtected: booleanField(config, 'createProtected'),
              }
            : undefined,
        ),
        payload,
        options,
      );
      return;
    }
    case 'interface': {
      const id = { interfaceName: name, transportRequest };
      await runSequence(
        label,
        sourceSteps(
          client.getInterface(),
          id,
          create ? { ...id, packageName, description } : undefined,
        ),
        payload,
        options,
      );
      return;
    }
    case 'program': {
      const id = { programName: name, transportRequest };
      await runSequence(
        label,
        sourceSteps(
          client.getProgram(),
          id,
          create ? { ...id, packageName, description } : undefined,
        ),
        payload,
        options,
      );
      return;
    }
    case 'transformation': {
      const id = { transformationName: name, transportRequest };
      await runSequence(
        label,
        sourceSteps(
          client.getTransformation(),
          id,
          create
            ? {
                ...id,
                packageName,
                description,
                transformationType: detectTransformationType(payload),
              }
            : undefined,
        ),
        payload,
        options,
      );
      return;
    }
    case 'structure': {
      const id = { structureName: name, transportRequest };
      await runSequence(
        label,
        sourceSteps(
          client.getStructure(),
          id,
          create ? { ...id, packageName, description } : undefined,
        ),
        payload,
        options,
      );
      return;
    }
    case 'table': {
      const id = { tableName: name, transportRequest };
      await runSequence(
        label,
        sourceSteps(
          client.getTable(),
          id,
          create ? { ...id, packageName, description } : undefined,
        ),
        payload,
        options,
      );
      return;
    }
    case 'appendStructure': {
      const id = { appendStructureName: name, transportRequest };
      const baseObject = stringField(config, 'baseObject');
      if (create && !baseObject) {
        throw new Error(
          `appendStructure ${name}: missing baseObject (cannot create)`,
        );
      }
      await runSequence(
        label,
        sourceSteps(
          client.getAppendStructure(),
          id,
          create ? { ...id, packageName, description, baseObject } : undefined,
        ),
        payload,
        options,
      );
      return;
    }
    case 'ddl': {
      const id = { ddlName: name, transportRequest };
      await runSequence(
        label,
        sourceSteps(
          client.getDdl(),
          id,
          create ? { ...id, packageName, description } : undefined,
        ),
        payload,
        options,
      );
      return;
    }
    case 'scalarFunction': {
      const id = { scalarFunctionName: name, transportRequest };
      await runSequence(
        label,
        sourceSteps(
          client.getScalarFunction(),
          id,
          create ? { ...id, packageName, description } : undefined,
        ),
        payload,
        options,
      );
      return;
    }
    case 'scalarFunctionImplementation': {
      const scalarFunctionName = stringField(config, 'scalarFunctionName');
      if (!scalarFunctionName) {
        throw new Error(
          `scalarFunctionImplementation ${name}: missing scalarFunctionName (cannot restore)`,
        );
      }
      const id = {
        implementationName: name,
        scalarFunctionName,
        transportRequest,
      };
      await runSequence(
        label,
        sourceSteps(
          client.getScalarFunctionImplementation(),
          id,
          create
            ? {
                ...id,
                packageName,
                description,
                engineValue:
                  oneOf(config.engineValue, ['sqlEngine', 'amdpEngine']) ??
                  'sqlEngine',
              }
            : undefined,
        ),
        payload,
        options,
      );
      return;
    }
    case 'functionModule': {
      const functionGroupName = requireGroup(node);
      const id = {
        functionGroupName,
        functionModuleName: name,
        transportRequest,
      };
      await runSequence(
        label,
        sourceSteps(
          client.getFunctionModule(),
          id,
          create ? { ...id, description } : undefined,
        ),
        payload,
        options,
      );
      return;
    }
    case 'functionInclude': {
      const functionGroupName = requireGroup(node);
      // The TOP include comes with its function group, so it is only ever
      // written; a create would be refused as "already exists".
      const isTop =
        name.toUpperCase() === `L${functionGroupName.toUpperCase()}TOP`;
      const id = { functionGroupName, includeName: name, transportRequest };
      await runSequence(
        label,
        sourceSteps(
          client.getFunctionInclude(),
          id,
          create && !isTop ? { ...id, description } : undefined,
        ),
        payload,
        options,
      );
      return;
    }
    case 'serviceDefinition': {
      const id = { serviceDefinitionName: name, transportRequest };
      await runSequence(
        label,
        sourceSteps(
          client.getServiceDefinition(),
          id,
          create ? { ...id, packageName, description } : undefined,
        ),
        payload,
        options,
      );
      return;
    }
    case 'metadataExtension': {
      const id = { name, transportRequest };
      await runSequence(
        label,
        sourceSteps(
          client.getMetadataExtension(),
          id,
          create ? { ...id, packageName, description } : undefined,
        ),
        payload,
        options,
      );
      return;
    }
    case 'behaviorDefinition': {
      const id = { name, transportRequest };
      // Older backups lack these two in the config; the source states both.
      const fromSource = payload ? parseBdefSource(payload) : {};
      await runSequence(
        label,
        sourceSteps(
          client.getBehaviorDefinition(),
          id,
          create
            ? {
                ...id,
                packageName,
                description,
                rootEntity:
                  stringField(config, 'rootEntity') ?? fromSource.rootEntity,
                implementationType:
                  oneOf(config.implementationType, [
                    'Managed',
                    'Unmanaged',
                    'Abstract',
                    'Projection',
                  ]) ?? fromSource.implementationType,
              }
            : undefined,
        ),
        payload,
        options,
      );
      return;
    }
    case 'behaviorImplementation': {
      const behaviorDefinition =
        stringField(config, 'behaviorDefinition') ??
        parseBehaviorDefinitionFromClass(payload);
      if (create && !behaviorDefinition) {
        throw new Error(
          `behaviorImplementation ${name}: the backup names no behavior definition (cannot create)`,
        );
      }
      const id = { className: name, transportRequest };
      await runSequence(
        label,
        sourceSteps(
          client.getBehaviorImplementation(),
          id,
          create && behaviorDefinition
            ? { ...id, packageName, description, behaviorDefinition }
            : undefined,
        ),
        payload,
        options,
      );
      return;
    }
    case 'enhancement': {
      const enhancementType =
        oneOf(config.enhancementType, [
          'enhoxh',
          'enhoxhb',
          'enhoxhh',
          'enhsxs',
          'enhsxsb',
        ]) ?? 'enhoxh';
      const id = { enhancementName: name, enhancementType, transportRequest };
      await runSequence(
        label,
        sourceSteps(
          client.getEnhancement(),
          id,
          create
            ? {
                ...id,
                packageName,
                description,
                enhancementSpot: stringField(config, 'enhancementSpot'),
                badiDefinition: stringField(config, 'badiDefinition'),
              }
            : undefined,
        ),
        payload,
        options,
      );
      return;
    }
    case 'accessControl': {
      const id = { accessControlName: name, transportRequest };
      await runSequence(
        label,
        sourceSteps(
          client.getAccessControl(),
          id,
          create ? { ...id, packageName, description } : undefined,
        ),
        payload,
        options,
      );
      return;
    }
    default:
      throw new Error(`Restore is not implemented for ${label}`);
  }
}

function configOf(node: BackupTreeNode): BackupConfig {
  if (node.config) return node.config;
  // A package backed up without a config still carries its document.
  if (node.type === 'package' && node.codeBase64 && node.codeFormat === 'xml') {
    try {
      return { ...parsePackageConfig(decodeBase64(node.codeBase64)) };
    } catch {
      logVerbose(2, `  Could not parse XML config for package ${node.name}`);
    }
  }
  return {};
}

/** The backed-up document, or nothing when the backup kept none. */
function documentPayload(
  node: BackupTreeNode,
  payload: string | undefined,
): string | undefined {
  return node.codeFormat === 'xml' ? payload : undefined;
}

function requireGroup(node: BackupTreeNode): string {
  if (!node.functionGroupName) {
    throw new Error(
      `${node.type} ${node.name}: the backup names no function group (cannot restore)`,
    );
  }
  return node.functionGroupName;
}

/**
 * A package is created when it is missing and left alone when it exists.
 *
 * Its document is not written back: it carries the source system's software
 * component, transport layer and super package, which the target need not
 * have, and the `--software-component` / `--transport-layer` /
 * `--super-package` overrides exist precisely because they differ.
 */
async function writePackage(
  client: AdtClient,
  node: BackupTreeNode,
  config: BackupConfig,
  options: WriteObjectOptions,
): Promise<void> {
  if (options.mode === 'update') {
    logVerbose(2, `  [KEEP] package ${node.name} exists; not rewritten`);
    return;
  }

  const backedUpSuper = stringField(config, 'superPackage');
  const superPackage =
    backedUpSuper && options.backupPackageNames?.has(backedUpSuper)
      ? backedUpSuper
      : (options.superPackage ?? backedUpSuper);
  if (!superPackage) {
    throw new Error(
      `Package ${node.name} cannot be created: superPackage is missing.`,
    );
  }
  const softwareComponent =
    options.softwareComponent ??
    stringField(config, 'softwareComponent') ??
    'ZLOCAL';
  const transportLayer =
    options.transportLayer ?? stringField(config, 'transportLayer');

  logVerbose(
    3,
    `  Creating package ${node.name} (Layer: ${transportLayer}, SoftwareComp: ${softwareComponent})`,
  );
  requireOk(
    await client.getPackage().create(
      {
        packageName: node.name,
        superPackage,
        description: stringField(config, 'description') ?? node.name,
        packageType: stringField(config, 'packageType'),
        softwareComponent,
        transportLayer,
        applicationComponent: stringField(config, 'applicationComponent'),
        transportRequest: options.transportRequest?.trim() || undefined,
        recordChanges: true,
      },
      refused,
    ),
    `create package ${node.name}`,
  );
  // Nothing tells us when a new package is usable as a parent; the objects
  // created under it next are refused if it is not. A short pause, as before.
  await delay(2000);
}

/**
 * A service binding is created, then given its backed-up publication state.
 *
 * A binding is not edited: its `update` is its publication, judged by
 * `analysePublication` (SAP answers a refused publication inside a 200). A
 * binding just created is unpublished, so only publishing is asked for then.
 */
async function writeServiceBinding(
  client: AdtClient,
  name: string,
  config: BackupConfig,
  context: {
    create: boolean;
    description: string;
    packageName?: string;
    transportRequest?: string;
  },
): Promise<void> {
  const binding = client.getServiceBinding();
  if (context.create) {
    requireOk(
      await binding.create(
        {
          bindingName: name,
          packageName: context.packageName,
          description: context.description,
          serviceDefinitionName: stringField(config, 'serviceDefinitionName'),
          serviceName: stringField(config, 'serviceName'),
          serviceVersion: stringField(config, 'serviceVersion'),
          bindingVariant: oneOf(config.bindingVariant, [
            'ODATA_V2_UI',
            'ODATA_V2_WEB_API',
            'ODATA_V4_UI',
            'ODATA_V4_WEB_API',
          ]),
          transportRequest: context.transportRequest,
        },
        refused,
      ),
      `create serviceBinding ${name}`,
    );
  }

  const desired = oneOf(config.desiredPublicationState, [
    'published',
    'unpublished',
  ]);
  const serviceType = oneOf(config.serviceType, ['odatav2', 'odatav4']);
  if (!desired || !serviceType) return;
  if (context.create && desired === 'unpublished') return;

  // A binding just created has no active version, and publishing it answers
  // "Service Binding … does not exist" inside a 200. It is activated first;
  // the service's information read (`generateServiceBinding`, a GET) is not
  // what is missing — measured: after the GET the publish still fails, after
  // the activation it succeeds.
  if (context.create) {
    requireOk(
      await binding.activate(
        { bindingName: name },
        { analyse: analyseActivation },
      ),
      `activate serviceBinding ${name}`,
    );
  }

  // The publication runs under the binding's lock, as Eclipse runs it; the
  // lock is released whatever the job answered. A lock an open editor holds
  // is not a reason to stop: the publication does not need ours, and Eclipse
  // itself carries on past its own 403 (measured).
  const handle = requireOk(
    await binding.lock({ bindingName: name }, { analyse: editorHoldsLock }),
    `lock serviceBinding ${name}`,
  );
  if (!handle) {
    logVerbose(
      1,
      `  [!] serviceBinding:${name} is locked by an editor; publishing without the lock`,
    );
  }
  try {
    const answer = await binding.update(
      { bindingName: name, desiredPublicationState: desired, serviceType },
      { analyse: analysePublication, timeout: PUBLICATION_TIMEOUT_MS },
    );
    if (!answer.ok) {
      throw new AdtCallError(
        `${desired === 'published' ? 'publish' : 'unpublish'} serviceBinding ${name}`,
        answer.getError(),
      );
    }
  } finally {
    if (handle) {
      await binding.unlock({ bindingName: name }, handle as string, refused);
    }
  }
}

/**
 * A binding's LOCK, read by `analyseException` — except the refusal an open
 * editor causes (`403`, "… is currently editing" / "You are already
 * editing"), which is no failure here: the publication goes ahead without a
 * lock of ours. Any other 403 — an authorization, say — stays a refusal.
 */
const editorHoldsLock: IAnalyse = (verdict, answer) => {
  const judged = analyseException(verdict, answer);
  if (judged === ADT_NO_FAILURE) return judged;
  const text = `${judged.message}\n${String(judged.response?.data ?? '')}`;
  return judged.response?.status === 403 && /editing/i.test(text)
    ? ADT_NO_FAILURE
    : judged;
};

/**
 * How long a publication job may take. Measured at 133 s on an idle system
 * and minutes on a loaded one; the library's 120 s default ends the request
 * before the job answers. The wait is on the job's own answer — nothing polls.
 */
const PUBLICATION_TIMEOUT_MS = 15 * 60 * 1000;

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
