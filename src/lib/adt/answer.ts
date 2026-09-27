import type { IAdtMessageFailure } from '@mcp-abap-adt/adt-strategies';
import type { IAdtError, IAdtResponse } from '@mcp-abap-adt/interfaces-adt';

/**
 * Reading `IAdtResponse` the way this CLI needs it.
 *
 * adt-clients answers every call with the contract and throws only for its
 * own causes; whether an answer is "absent", "empty" or "refused" is the
 * consumer's decision. These are the backuper's decisions, in one place.
 */

/** Whether a verdict came from an adt-strategies reading, with its messages. */
function hasMessages(error: IAdtError): error is IAdtMessageFailure {
  return Array.isArray((error as Partial<IAdtMessageFailure>).messages);
}

/**
 * What SAP said, as one line: the verdict's message plus every message the
 * strategy read out of the document (`analyseActivation`, `analyseDeletion`,
 * `analyseException` carry them in `messages`).
 */
export function describeFailure(error: IAdtError): string {
  const parts = [error.message];
  if (hasMessages(error)) {
    for (const m of error.messages) {
      const text = m.text.trim();
      if (text && !parts.some((p) => p.includes(text))) {
        parts.push(m.type ? `[${m.type}] ${text}` : text);
      }
    }
  }
  const status = error.response?.status;
  const head = status ? `HTTP ${status}: ` : '';
  return head + parts.filter(Boolean).join(' | ');
}

/** A failed ADT call, carrying SAP's answer rather than a sentence of ours. */
export class AdtCallError extends Error {
  readonly adtError: IAdtError;

  constructor(what: string, adtError: IAdtError) {
    super(`${what}: ${describeFailure(adtError)}`);
    this.name = 'AdtCallError';
    this.adtError = adtError;
  }

  /** The HTTP status of the answer, when there was one. */
  get status(): number | undefined {
    return this.adtError.response?.status;
  }
}

/**
 * The status that means "there is no such object": ADT answers 404 for an
 * object read that finds nothing (410 for one that is gone). Everything else
 * — a 403, a 500, a session that died — is a failure and must not pass for
 * absence.
 */
export function isAbsence(error: IAdtError): boolean {
  const status = error.response?.status;
  return status === 404 || status === 410;
}

/** `value` as text, without pretending an object was ever a string. */
export function textOf(value: unknown): string {
  if (value === undefined || value === null) return '';
  return typeof value === 'string' ? value : JSON.stringify(value);
}

/**
 * The document a read answered, or `null` when there is nothing to take.
 *
 * `null` covers both shapes absence arrives in: a 404/410, and a `200` with
 * zero bytes — which `source/main` and a not-yet-ready document read answer
 * for an object that is missing *and* for one that is empty. The two cannot be
 * told apart from the answer, and for a backup they are the same: there is no
 * payload to keep. Any other failure throws with SAP's message.
 */
export function readAnswer(
  response: IAdtResponse<unknown>,
  what: string,
): string | null {
  if (!response.ok) {
    const error = response.getError();
    if (isAbsence(error)) return null;
    throw new AdtCallError(what, error);
  }
  const text = textOf(response.getResult().value);
  return text.trim().length === 0 ? null : text;
}

/** The value of a call that must have succeeded; SAP's refusal otherwise. */
export function requireOk<T>(response: IAdtResponse<T>, what: string): T {
  if (!response.ok) {
    throw new AdtCallError(what, response.getError());
  }
  return response.getResult().value;
}
