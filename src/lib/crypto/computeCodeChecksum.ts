import { decodeBase64 } from './decodeBase64';
import { hashText } from './hashText';

export function computeCodeChecksum(codeBase64: string): string {
  return hashText(decodeBase64(codeBase64));
}
