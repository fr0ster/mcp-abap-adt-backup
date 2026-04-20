import type { AdtClient } from '@mcp-abap-adt/adt-clients';
import type { ObjectSpec } from '../types';
import { responseToText } from '../utils/responseToText';
import { extractMetadata } from '../xml/extractMetadata';

export async function readBasicMetadata(
  client: AdtClient,
  spec: ObjectSpec,
): Promise<{ description?: string; packageName?: string }> {
  switch (spec.type) {
    case 'class': {
      const state = await client
        .getClass()
        .readMetadata({ className: spec.name });
      const xml = responseToText(state.metadataResult);
      return xml ? extractMetadata(xml) : {};
    }
    case 'interface': {
      const state = await client
        .getInterface()
        .readMetadata({ interfaceName: spec.name });
      const xml = responseToText(state.metadataResult);
      return xml ? extractMetadata(xml) : {};
    }
    case 'program': {
      const state = await client
        .getProgram()
        .readMetadata({ programName: spec.name });
      const xml = responseToText(state.metadataResult);
      return xml ? extractMetadata(xml) : {};
    }
    case 'transformation': {
      const state = await client
        .getTransformation()
        .readMetadata({ transformationName: spec.name });
      const xml = responseToText(state.metadataResult);
      return xml ? extractMetadata(xml) : {};
    }
    case 'structure': {
      const state = await client
        .getStructure()
        .readMetadata({ structureName: spec.name });
      const xml = responseToText(state.metadataResult);
      return xml ? extractMetadata(xml) : {};
    }
    case 'table': {
      const state = await client
        .getTable()
        .readMetadata({ tableName: spec.name });
      const xml = responseToText(state.metadataResult);
      return xml ? extractMetadata(xml) : {};
    }
    case 'tableType': {
      const state = await client
        .getTableType()
        .readMetadata({ tableTypeName: spec.name });
      const xml = responseToText(state.metadataResult);
      return xml ? extractMetadata(xml) : {};
    }
    case 'functionModule': {
      if (!spec.functionGroupName) {
        return {};
      }
      const state = await client.getFunctionModule().readMetadata({
        functionGroupName: spec.functionGroupName,
        functionModuleName: spec.name,
      });
      const xml = responseToText(state.metadataResult);
      return xml ? extractMetadata(xml) : {};
    }
    default:
      return {};
  }
}
