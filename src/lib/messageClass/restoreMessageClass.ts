import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import { logVerbose } from '../cli/logVerbose';
import type { RestoreMode } from '../types';
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
 * Not transactional — each getMessageClassMessage() call GET-locks-PUTs the
 * whole class. Idempotent and safe to re-run.
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
  client: AdtClient,
  parsed: ParsedMessageClass,
  opts: RestoreMessageClassOptions,
): Promise<void> {
  const { mode, name, description, packageName, transportRequest } = opts;
  const attempts = opts.retryAttempts ?? 6;
  const delayMs = opts.retryDelayMs ?? 15000;
  const mc = client.getMessageClass();
  const mcm = client.getMessageClassMessage();

  if (mode === 'create') {
    await mc.create({ name, description, packageName, transportRequest });
  } else {
    // update (or upsert already resolved): sync the shell description
    await mc.update({ name, description, packageName, transportRequest });
  }

  for (const msg of parsed.messages) {
    await withEditableRetry(
      () =>
        mcm.update({
          className: name,
          msgno: msg.msgno,
          msgtext: msg.msgtext,
          selfExplanatory: msg.selfExplanatory,
          description: msg.description,
          transportRequest,
        }),
      { attempts, delayMs, name },
    );
  }

  if (mode !== 'create') {
    const current = await mc.read({ name });
    const keep = new Set(parsed.messages.map((m) => m.msgno));
    const existing = current?.messageClass?.messages ?? [];
    for (const cm of existing) {
      if (!keep.has(cm.msgno)) {
        await mcm.delete({
          className: name,
          msgno: cm.msgno,
          transportRequest,
        });
      }
    }
  }
}

/**
 * Retry `fn` while it fails with the transient post-create "object not yet
 * editable" error (EU510 / ExceptionResourceNoAccess / 403), waiting `delayMs`
 * between attempts. Any other error is rethrown immediately. If the window is
 * exhausted, throw a clear, actionable error.
 */
async function withEditableRetry<T>(
  fn: () => Promise<T>,
  ctx: { attempts: number; delayMs: number; name: string },
): Promise<T> {
  const { attempts, delayMs, name } = ctx;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (error) {
      if (!isTransientEditLock(error)) {
        throw error;
      }
      if (i < attempts - 1) {
        logVerbose(
          1,
          `  [WAIT] message class ${name} not yet editable (async registration); retry ${i + 1}/${attempts - 1} in ${Math.round(delayMs / 1000)}s`,
        );
        await delay(delayMs);
      }
    }
  }
  throw new Error(
    `message class ${name}: shell created but still not editable after ${attempts} attempts ` +
      '(the system registers new message classes asynchronously). Re-run restore later to populate its messages.',
  );
}

/**
 * True when the error is the transient "class just created, not yet editable"
 * signal. Matches the SAP edit-lock markers (EU510 / ExceptionResourceNoAccess /
 * "currently editing") only — a bare HTTP 403 without these markers is a real
 * authorization failure and must NOT be retried (it would waste the whole retry
 * window and end with a misleading "not yet editable" message).
 */
function isTransientEditLock(error: unknown): boolean {
  const parts: string[] = [];
  if (error instanceof Error && error.message) {
    parts.push(error.message);
  }
  const data = (error as { response?: { data?: unknown } })?.response?.data;
  if (data) {
    parts.push(typeof data === 'string' ? data : JSON.stringify(data));
  }
  const haystack = parts.join(' ');
  return /EU510|ResourceNoAccess|currently editing/i.test(haystack);
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
