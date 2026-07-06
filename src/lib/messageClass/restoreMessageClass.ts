import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import type { RestoreMode } from '../types';
import type { ParsedMessageClass } from './types';

export interface RestoreMessageClassOptions {
  mode: RestoreMode;
  name: string;
  description?: string;
  packageName?: string;
  transportRequest?: string;
}

/**
 * Restore a message class as one unit: create/update the shell, upsert every
 * message from the backup, and (update mode only) delete target messages that
 * are absent from the backup so the target's message set equals the backup.
 *
 * Not transactional — each getMessageClassMessage() call GET-locks-PUTs the
 * whole class. Idempotent and safe to re-run.
 */
export async function restoreMessageClass(
  client: AdtClient,
  parsed: ParsedMessageClass,
  opts: RestoreMessageClassOptions,
): Promise<void> {
  const { mode, name, description, packageName, transportRequest } = opts;
  const mc = client.getMessageClass();
  const mcm = client.getMessageClassMessage();

  if (mode === 'create') {
    await mc.create({ name, description, packageName, transportRequest });
  } else {
    // update (or upsert already resolved): sync the shell description
    await mc.update({ name, description });
  }

  for (const msg of parsed.messages) {
    await mcm.update({
      className: name,
      msgno: msg.msgno,
      msgtext: msg.msgtext,
      selfExplanatory: msg.selfExplanatory,
      description: msg.description,
      transportRequest,
    });
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
