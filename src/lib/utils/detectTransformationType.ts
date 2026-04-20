import type { ITransformationConfig } from '@mcp-abap-adt/adt-clients';

export function detectTransformationType(
  source?: string,
): ITransformationConfig['transformationType'] {
  if (source && /<\?sap\.transform\s+simple\s*\?>/i.test(source)) {
    return 'SimpleTransformation';
  }
  return 'XSLTProgram';
}
