import type { ParsedMessageClass } from './types';

/**
 * Stable, comparable string form of a message class. Messages are sorted by
 * msgno; only user-authored fields are included (class description + each
 * message's msgno/msgtext/selfExplanatory/description). Volatile server
 * metadata (masterSystem, responsible, timestamps) is intentionally excluded.
 */
export function canonicalizeMessageClass(cls: ParsedMessageClass): string {
  const lines: string[] = [`class|${cls.description ?? ''}`];
  const messages = [...(cls.messages ?? [])].sort((a, b) =>
    a.msgno.localeCompare(b.msgno),
  );
  for (const m of messages) {
    lines.push(
      `${m.msgno}|${m.msgtext ?? ''}|${m.selfExplanatory ? '1' : '0'}|${m.description ?? ''}`,
    );
  }
  return lines.join('\n');
}
