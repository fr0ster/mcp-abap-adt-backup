import type { SupportedType } from '../types';

export function normalizeType(rawType: string): SupportedType {
  const normalized = rawType.trim().toLowerCase();
  const map: Record<string, SupportedType> = {
    package: 'package',
    domain: 'domain',
    dataelement: 'dataElement',
    'data-element': 'dataElement',
    data_element: 'dataElement',
    structure: 'structure',
    table: 'table',
    tabletype: 'tableType',
    table_type: 'tableType',
    view: 'view',
    class: 'class',
    interface: 'interface',
    program: 'program',
    functiongroup: 'functionGroup',
    function_group: 'functionGroup',
    functionmodule: 'functionModule',
    function_module: 'functionModule',
    servicedefinition: 'serviceDefinition',
    service_definition: 'serviceDefinition',
    metadataextension: 'metadataExtension',
    metadata_extension: 'metadataExtension',
    behaviordefinition: 'behaviorDefinition',
    behavior_definition: 'behaviorDefinition',
    behaviorimplementation: 'behaviorImplementation',
    behavior_implementation: 'behaviorImplementation',
    enhancement: 'enhancement',
    unittest: 'unitTest',
    unit_test: 'unitTest',
    cdsunittest: 'cdsUnitTest',
    cds_unit_test: 'cdsUnitTest',
  };
  const mapped = map[normalized];
  if (!mapped) {
    throw new Error(`Unsupported object type: ${rawType}`);
  }
  return mapped;
}
