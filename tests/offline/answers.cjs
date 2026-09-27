'use strict';
// IAdtResponse as adt-clients 23 answers it, for the offline fakes.

/** A success carrying `value` (the document, a run id, a lock handle...). */
function ok(value) {
  return { ok: true, getResult: () => ({ value }) };
}

/** A failure the way a verdict names one: SAP's text and the wire status. */
function fail(status, message, adtType) {
  const error = {
    origin: status >= 400 ? 'connection' : 'refusal',
    message,
    adtType,
    response: { status, data: message, headers: {} },
  };
  return { ok: false, getError: () => error };
}

module.exports = { ok, fail };
