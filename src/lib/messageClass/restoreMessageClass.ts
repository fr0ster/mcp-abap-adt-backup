import { analyseException } from '@mcp-abap-adt/adt-strategies';
import type { IAdtError, IAdtResponse } from '@mcp-abap-adt/interfaces-adt';
import {
  AdtCallError,
  describeFailure,
  requireOk,
  textOf,
} from '../adt/answer';
import type { RestoreTarget } from '../adt/RestoreTarget';
import { logVerbose } from '../cli/logVerbose';
import type { RestoreMode } from '../types';
import { parseMessageClassXml } from './parseMessageClassXml';
import { readMessageClass } from './readMessageClass';
import type { ParsedMessageClass } from './types';

export interface RestoreMessageClassOptions {
  mode: RestoreMode;
  name: string;
  description?: string;
  packageName?: string;
  transportRequest?: string;
  /** Retry attempts for the post-create "not yet editable" window (default 6). */
  retryAttempts?: number;
  /** Backoff in ms between retries (default 15000). */
  retryDelayMs?: number;
}

/**
 * Restore a message class as one unit: create/update the shell, upsert every
 * message from the backup, and (update mode only) delete target messages that
 * are absent from the backup so the target's message set equals the backup.
 *
 * Not transactional — each message write GET-locks-PUTs the whole class
 * (adt-clients keeps that one read-modify-write, a message being a row of its
 * class). Idempotent and safe to re-run.
 *
 * Post-create timing: on some systems (e.g. BTP ABAP trial) a freshly created
 * message class is not immediately editable — `LOCK_MSG` returns 403 EU510
 * ("currently editing") for several minutes while the object is registered
 * asynchronously in the background. This affects any session, not just the
 * creating one, so it is a server-side delay, not a leftover lock. We retry the
 * first message upsert with backoff to give the system time; if the object is
 * still not editable after the retry window, we throw a clear error — the shell
 * exists, and re-running restore later (idempotent) populates the messages once
 * the object has settled.
 */
export async function restoreMessageClass(
  target: RestoreTarget,
  parsed: ParsedMessageClass,
  opts: RestoreMessageClassOptions,
): Promise<void> {
  const { mode, name, description, packageName, transportRequest } = opts;
  const attempts = opts.retryAttempts ?? 6;
  const delayMs = opts.retryDelayMs ?? 15000;
  const { client, messages } = target;
  const mc = client.getMessageClass();

  if (mode === 'create') {
    requireOk(
      await mc.create(
        { name, description, packageName, transportRequest },
        { analyse: analyseException },
      ),
      `create messageClass ${name}`,
    );
  } else if (description !== undefined) {
    await syncDescription(target, name, description, transportRequest);
  }

  for (const msg of parsed.messages) {
    await withEditableRetry(
      () =>
        messages.update(
          {
            className: name,
            msgno: msg.msgno,
            msgtext: msg.msgtext,
            selfExplanatory: msg.selfExplanatory,
            description: msg.description,
            transportRequest,
          },
          { analyse: analyseException },
        ),
      { attempts, delayMs, name, what: `write message ${msg.msgno}` },
    );
  }

  if (mode !== 'create') {
    const current = await readMessageClass(client, name);
    const keep = new Set(parsed.messages.map((m) => m.msgno));
    for (const cm of current?.messages ?? []) {
      if (!keep.has(cm.msgno)) {
        requireOk(
          await messages.delete(
            { className: name, msgno: cm.msgno, transportRequest },
            { analyse: analyseException },
          ),
          `delete message ${cm.msgno} of messageClass ${name}`,
        );
      }
    }
  }
}

/**
 * Set the class's own description, the way adt-clients 23 leaves it to the
 * caller: read the document, edit it, lock, write it whole, unlock.
 * `updateMetadata` sends the document it is given and reads nothing itself.
 */
async function syncDescription(
  target: RestoreTarget,
  name: string,
  description: string,
  transportRequest?: string,
): Promise<void> {
  const mc = target.client.getMessageClass();
  const id = { name, transportRequest };
  const current = requireOk(
    await mc.readMetadata({ name }, { analyse: analyseException }),
    `read messageClass ${name}`,
  );
  const xml = textOf(current);
  if (parseMessageClassXml(xml).description === description) return;

  const edited = withClassDescription(xml, description);
  const lockHandle = requireOk(
    await mc.lock(id, { analyse: analyseException }),
    `lock messageClass ${name}`,
  );
  if (!lockHandle) {
    throw new Error(
      `lock messageClass ${name}: SAP answered without a lock handle`,
    );
  }
  let writeError: unknown;
  try {
    requireOk(
      await mc.updateMetadata(id, {
        source: edited,
        lockHandle,
        analyse: analyseException,
      }),
      `write messageClass ${name}`,
    );
  } catch (error) {
    writeError = error;
  }
  const unlocked = await mc.unlock(id, lockHandle, {
    analyse: analyseException,
  });
  if (writeError !== undefined) throw writeError;
  requireOk(unlocked, `unlock messageClass ${name}`);
}

const escapeAttribute = (value: string): string =>
  value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

/**
 * The document with the class's own `adtcore:description` set. Only the root
 * start tag is touched: every message carries an `adtcore:description` too,
 * and the first one in the text is the class's only when the root has one.
 */
export function withClassDescription(xml: string, description: string): string {
  const root = /<mc:messageClass\b[^>]*>/.exec(xml);
  if (!root) {
    throw new Error('Not a message class document: no <mc:messageClass> root');
  }
  const tag = root[0];
  const value = `adtcore:description="${escapeAttribute(description)}"`;
  const updated = /\badtcore:description="[^"]*"/.test(tag)
    ? tag.replace(/\badtcore:description="[^"]*"/, value)
    : tag.replace(/^<mc:messageClass\b/, `<mc:messageClass ${value}`);
  return (
    xml.slice(0, root.index) + updated + xml.slice(root.index + tag.length)
  );
}

/**
 * Run `fn` again while SAP answers with the transient post-create "object not
 * yet editable" refusal (EU510 / ExceptionResourceNoAccess), waiting `delayMs`
 * between attempts. Any other refusal is thrown at once, with SAP's message.
 * If the window is exhausted, throw a clear, actionable error.
 */
async function withEditableRetry<T>(
  fn: () => Promise<IAdtResponse<T>>,
  ctx: { attempts: number; delayMs: number; name: string; what: string },
): Promise<T> {
  const { attempts, delayMs, name, what } = ctx;
  for (let i = 0; i < attempts; i++) {
    const answer = await fn();
    if (answer.ok) return answer.getResult().value;
    const error = answer.getError();
    if (!isTransientEditLock(error)) {
      throw new AdtCallError(`${what} of messageClass ${name}`, error);
    }
    if (i < attempts - 1) {
      logVerbose(
        1,
        `  [WAIT] message class ${name} not yet editable (async registration); retry ${i + 1}/${attempts - 1} in ${Math.round(delayMs / 1000)}s`,
      );
      await delay(delayMs);
    }
  }
  throw new Error(
    `message class ${name}: shell created but still not editable after ${attempts} attempts ` +
      '(the system registers new message classes asynchronously). Re-run restore later to populate its messages.',
  );
}

/**
 * True when SAP's answer is the transient "class just created, not yet
 * editable" refusal. Matches the edit-lock markers (EU510 /
 * ExceptionResourceNoAccess / "currently editing") only — a bare 403 without
 * them is a real authorization failure and must NOT be retried.
 */
function isTransientEditLock(error: IAdtError): boolean {
  const haystack = [
    describeFailure(error),
    error.adtType ?? '',
    textOf(error.response?.data),
  ].join(' ');
  return /EU510|ResourceNoAccess|currently editing/i.test(haystack);
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
