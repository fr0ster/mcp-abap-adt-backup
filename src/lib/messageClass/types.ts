// Local structural types for message-class JSON payloads. The adt-clients
// IParsedMessage / IParsedMessageClass are not exported from the package root,
// so we mirror the shape we depend on here.
export interface ParsedMessage {
  msgno: string;
  msgtext: string;
  selfExplanatory?: boolean;
  description?: string;
}

export interface ParsedMessageClass {
  name: string;
  description?: string;
  packageName?: string;
  language?: string;
  masterLanguage?: string;
  messages: ParsedMessage[];
}
