const commonOptions = [
  'Common Options:',
  '  --destination <name>      Destination name for AuthBroker stores',
  '  --env <file>              Path to .env file',
  '  --auth-root <path>        Root folder with auth configs',
  '  --log-file <path>         Write console output to a file',
  '  --debug-adt               Enable ADT/connection logs',
  '  -v, -vv, -vvv             Verbosity levels',
].join('\n');

const commands: Record<string, string> = {
  backup: `
Usage: adt-backup backup [options]

Backs up ABAP objects or packages.

Options:
  --objects <list>          Comma-separated list of objects (type:name)
  --package <name>          Name of the package to backup recursively
  --output <file>           Output file (default: backup.yaml)

${commonOptions}

Examples:
  adt-backup backup --objects class:ZCL_TEST,view:ZV_TEST
  adt-backup backup --package ZPKG_TEST --output backup.yaml
`.trim(),

  restore: `
Usage: adt-backup restore [options]

Restores objects from a backup file.

Options:
  --input <file>            Backup file to restore
  --mode <mode>             Restore mode: create, update, upsert (default: upsert)
  --activate                Activate objects after restore (default for updates)
  --no-activate-on-create   Skip activation for new objects
  --no-activate-on-update   Skip activation for updated objects
  --force                   Force restore even if conflicts are found
  --strict                  Fail on any verification error
  --dangerous               Delete objects from system before restore (package only)
  --transport <request>     Transport request for changes
  --software-component <name> Override software component for packages

${commonOptions}

Examples:
  adt-backup restore --input backup.yaml --mode upsert --activate
  adt-backup restore --input backup.yaml --force --transport DEVK900001
`.trim(),

  diff: `
Usage: adt-backup diff [options]

Compares backup content with the current system state.

Options:
  --input <file>            Backup file to compare
  --object <type:name>      Specific object to compare
  --all                     Compare all objects in the backup
  --show-ok                 Show objects with no differences

${commonOptions}

Examples:
  adt-backup diff --input backup.yaml --all
  adt-backup diff --input backup.yaml --object class:ZCL_TEST
`.trim(),

  verify: `
Usage: adt-backup verify [options]

Verifies the integrity of a backup file (source-only).

Options:
  --input <file>            Backup file to verify
  --format <format>         Output format: text, json (default: text)
  --strict                  Fail on any verification error

${commonOptions}

Examples:
  adt-backup verify --input backup.yaml
`.trim(),

  validate: `
Usage: adt-backup validate [options]

Validates the internal checksums of a backup file.

Options:
  --input <file>            Backup file to validate
  --object <type:name>      Specific object to validate (optional)

${commonOptions}

Examples:
  adt-backup validate --input backup.yaml
`.trim(),

  extract: `
Usage: adt-backup extract [options]

Extracts a single object's source code from a backup file.

Options:
  --input <file>            Backup file
  --object <type:name>      Object to extract
  --out <file>              Output file path

${commonOptions}

Examples:
  adt-backup extract --input backup.yaml --object class:ZCL_TEST --out ZCL_TEST.abap
`.trim(),

  patch: `
Usage: adt-backup patch [options]

Patches an object's source code in a backup file.

Options:
  --input <file>            Backup file
  --object <type:name>      Object to patch
  --file <file>             File containing new source code
  --output <file>           Output backup file (defaults to input file)

${commonOptions}

Examples:
  adt-backup patch --input backup.yaml --object class:ZCL_TEST --file ZCL_TEST.abap
`.trim(),

  list: `
Usage: adt-backup list [options]

Lists contents of a backup file.

Options:
  --input <file>            Backup file
  --format <format>         Output format: text, json (default: text)
  --flat                    List flattened objects (for tree backups)
  --deps                    Show dependencies (tree structure only)

${commonOptions}

Examples:
  adt-backup list --input backup.yaml
  adt-backup list --input backup.yaml --flat
`.trim(),
};

export function usage(command?: string): string {
  if (command && commands[command]) {
    return commands[command];
  }

  return [
    'ADT Backup/Restore',
    '',
    'Usage: adt-backup <command> [options]',
    '',
    'Commands:',
    '  backup    Backup ABAP objects or packages',
    '  restore   Restore objects from backup',
    '  diff      Compare backup with system',
    '  verify    Verify backup integrity',
    '  validate  Validate backup checksums',
    '  extract   Extract object source',
    '  patch     Patch object source in backup',
    '  list      List backup contents',
    '',
    'Run "adt-backup <command> --help" for command-specific options.',
    '',
    commonOptions,
    '',
    'Object type examples:',
    '  class:ZCL_TEST',
    '  interface:ZIF_TEST',
    '  program:ZREP_TEST',
    '  view:ZV_TEST',
    '  domain:ZDOM_TEST',
    '  dataElement:ZDE_TEST',
    '  structure:ZST_TEST',
    '  table:ZT_TEST',
    '  tableType:ZTT_TEST',
    '  functionGroup:ZFG_TEST',
    '  functionModule:ZFG_TEST|ZFM_TEST',
    '  serviceDefinition:Z_I_SRV_DEF',
    '  metadataExtension:Z_I_SRV_EXT',
    '  behaviorDefinition:Z_I_BDEF',
  ].join('\n');
}
