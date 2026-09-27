import { type AdtClient, utilDocuments } from '@mcp-abap-adt/adt-clients';
import {
  analyseActivation,
  analyseException,
  utilActivationRunId,
  utilInactiveObjects,
} from '@mcp-abap-adt/adt-strategies';
import type { IObjectReference } from '@mcp-abap-adt/interfaces-adt';
import { describeFailure, requireOk, textOf } from '../adt/answer';
import { logVerbose } from '../cli/logVerbose';

/** How long one group activation may run before the CLI stops waiting. */
export const ACTIVATION_DEADLINE_MS = 300_000;

/*
 * `activationStatusIn` is ported from @mcp-abap-adt/adt-clients
 * (scripts/lib/activationRun.ts, at fb61b9b6): the one reading shared about an
 * activation wait. The wait itself is this CLI's, as adt-clients intends —
 * `activateObjectsGroup` is the POST that starts the run and nothing more
 * since 19.0.0.
 */

/** `runs:status` out of the run document, whatever prefix the server used. */
export function activationStatusIn(document: string): string {
  return document.match(/[\w:]*status="([^"]+)"/)?.[1] ?? '';
}

const keyOf = (ref: { type: string; name: string }): string =>
  `${ref.type}:${ref.name}`.toUpperCase();

function utilsOf(client: AdtClient) {
  return client.getUtils({
    ...utilDocuments,
    inactive: utilInactiveObjects,
    activation: utilActivationRunId,
  });
}

/** Which of `refs` the system lists as inactive. */
export async function findInactive(
  client: AdtClient,
  refs: IObjectReference[],
): Promise<IObjectReference[]> {
  const answer = await utilsOf(client).getInactiveObjects({
    analyse: analyseException,
  });
  const listed = requireOk(answer, 'read inactive objects').objects;
  const inactive = new Set(listed.map(keyOf));
  return refs.filter((ref) => inactive.has(keyOf(ref)));
}

export interface GroupActivationOutcome {
  /** The run finished and its results carry no error. */
  ok: boolean;
  /** SAP's messages, or why the wait ended. */
  messages: string[];
}

/**
 * Activate `refs` together and wait for the run to end.
 *
 * `activateObjectsGroup` answers the run id; `getActivationRun` with long
 * polling says what the run is doing, so the loop waits rather than spins;
 * `getActivationResults` holds the verdict, read by `analyseActivation`. The
 * deadline is this CLI's: past it the run may still finish on the server, and
 * the inactive list checked afterwards is what reports the state.
 */
export async function activateGroup(
  client: AdtClient,
  refs: IObjectReference[],
  deadlineMs: number = ACTIVATION_DEADLINE_MS,
): Promise<GroupActivationOutcome> {
  const utils = utilsOf(client);
  const started = await utils.activateObjectsGroup(refs, true, {
    analyse: analyseException,
  });
  if (!started.ok) {
    return { ok: false, messages: [describeFailure(started.getError())] };
  }
  const runId = started.getResult().value;
  if (!runId) {
    return {
      ok: false,
      messages: ['SAP started no activation run (no run id in the answer)'],
    };
  }

  let status = '';
  const deadline = Date.now() + deadlineMs;
  while (status !== 'finished' && Date.now() < deadline) {
    const run = await utils.getActivationRun(runId, {
      withLongPolling: true,
      analyse: analyseException,
    });
    if (!run.ok) {
      return { ok: false, messages: [describeFailure(run.getError())] };
    }
    status = activationStatusIn(textOf(run.getResult().value));
    logVerbose(3, `    activation run ${runId}: ${status || '(no status)'}`);
    if (status === 'error' || status === 'failed') break;
  }
  if (status !== 'finished' && status !== 'error' && status !== 'failed') {
    return {
      ok: false,
      messages: [
        `activation run ${runId} did not finish within ${Math.round(deadlineMs / 1000)}s`,
      ],
    };
  }

  const results = await utils.getActivationResults(runId, {
    analyse: analyseActivation,
  });
  if (!results.ok) {
    const error = results.getError();
    const messages =
      error.messages.length > 0
        ? error.messages.map((m) => `[${m.type}] ${m.text}`)
        : [describeFailure(error)];
    return { ok: false, messages };
  }
  if (status !== 'finished') {
    return {
      ok: false,
      messages: [`activation run ${runId} ended as ${status}`],
    };
  }
  return { ok: true, messages: [] };
}
