import type {
  AdtClient,
  AdtMessageClassMessage,
} from '@mcp-abap-adt/adt-clients';

/**
 * What a message class's rows are written with.
 *
 * `AdtClient.getMessageClassMessage()` is typed by a contract without
 * `delete` — a row is removed by a write of its class, not by a DELETE — while
 * `AdtMessageClassMessage` itself offers it. The restore needs both writes.
 */
export type MessageClassMessages = Pick<
  AdtMessageClassMessage,
  'update' | 'delete'
>;

/** The system a restore writes to. */
export interface RestoreTarget {
  client: AdtClient;
  messages: MessageClassMessages;
}
