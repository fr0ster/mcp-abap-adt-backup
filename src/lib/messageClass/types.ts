// The backup's message-class payload (stored as JSON). adt-clients reads no
// message class for its caller since 23.0.0, so this is the backup's own shape,
// filled by parseMessageClassXml.
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
