const commonOptions = [
  'Common Options:',
  '  --destination <name>      Target system name (from AuthBroker stores)',
  '  --target <name>           Alias for --destination',
  '  --env <file>              Path to .env file for target system',
  '  --env-path <file>         Alias for --env',
  '  --auth-root <path>        Root folder with auth configs',
  '  --mcp                     Enable MCP-compatible mode',
  '  --browser-auth-port <port> Port for OAuth callback server (default: 10001)',
  '  --log-file <path>         Write console output to a file',
  '  --debug-adt               Enable ADT/connection logs',
  '  -v, -vv, -vvv             Verbosity levels',
].join('\n');

const commands: Record<string, string> = {
  backup: `
Usage: adt-backup backup [options]

Backs up ABAP objects or packages from the source system.

Options:
  --objects <list>          Comma-separated list of objects (type:name)
  --package <name>          Name of the package to backup recursively
  --output <file>           Output file (default: backup.yaml)

${commonOptions}
`.trim(),

  tree: `
Usage: adt-backup tree [options]

Fetches package hierarchy and dependencies from the source system.

Options:
  --package <name>          Name of the package to analyze
  --output <file>           Output file (default: tree.yaml)

${commonOptions}
`.trim(),

  enrich: `
Usage: adt-backup enrich [options]

Populates a tree file with metadata and source code from the source system.

Options:
  --input <file>            Input tree YAML file
  --output <file>           Output backup file (defaults to input file)

${commonOptions}
`.trim(),

  plan: `
Usage: adt-backup plan [options]

Builds a dependency-based restoration sequence (offline).

Options:
  --input <file>            Backup file to analyze
  --output <file>           Output plan file (default: plan.yaml)
  --mode <mode>             Default action for all objects: create, update, upsert (default: create)

Examples:
  adt-backup plan --input backup.yaml --output plan.yaml
`.trim(),

  verify: `
Usage: adt-backup verify [options]

Updates a restoration plan with actual TARGET system state (online).

Options:
  --plan <file>             Plan file to update (required)
  --output <file>           Output plan file (defaults to input file)
  --skip-existing           Skip all existing objects (mark as 'skip' instead of 'update')
  --skip-unchanged          Skip unchanged objects only (source-mismatch still updated)

${commonOptions}

Examples:
  adt-backup verify --plan plan.yaml --target mdd-sk-dev
  adt-backup verify --plan plan.yaml --target mdd-sk-dev --skip-existing
  adt-backup verify --plan plan.yaml --target mdd-sk-dev --skip-unchanged
`.trim(),

  check: `
Usage: adt-backup check [options]

Compares backup file with the TARGET system (online).

Options:
  --input <file>            Backup file to check
  --format <format>         Output format: text, json (default: text)
  --strict                  Fail on any difference (source/package)

${commonOptions}

Examples:
  adt-backup check --input backup.yaml --target mdd-sk-dev
`.trim(),

  restore: `
Usage: adt-backup restore [options]

Executes a restoration plan on the TARGET system (online).

Options:
  --plan <file>             Pre-generated and verified plan file (required)
  --no-activate             Disable all activations (including group activation)
  --transport <request>     Transport request for changes in target system
  --software-component <name> Override software component for packages
  --transport-layer <name>   Override transport layer for packages
  --super-package <name>    Default super package for root packages

${commonOptions}

Examples:
  adt-backup restore --plan plan.yaml --target mdd-sk-dev
`.trim(),

  activate: `
Usage: adt-backup activate [options]

Activates existing objects in the TARGET system based on a plan file.
Useful after --skip-existing to activate objects that were skipped during restore.

Options:
  --plan <file>             Plan file to read (required)
  --filter <mode>           Which objects to activate: skip, update, or all (default: all)

${commonOptions}

Examples:
  adt-backup activate --plan plan.yaml --target mdd-sk-dev
  adt-backup activate --plan plan.yaml --target mdd-sk-dev --filter skip
`.trim(),

  diff: `
Usage: adt-backup diff [options]

Compares backup content with the TARGET system state.

Options:
  --input <file>            Backup file to compare
  --object <type:name>      Specific object to compare
  --all                     Compare all objects in the backup
  --show-ok                 Show objects with no differences

${commonOptions}
`.trim(),

  validate: `
Usage: adt-backup validate [options]

Validates the internal checksums of a backup file (offline).

Options:
  --input <file>            Backup file to validate
  --object <type:name>      Specific object to validate (optional)
`.trim(),

  list: `
Usage: adt-backup list [options]

Lists contents of a backup file (offline).

Options:
  --input <file>            Backup file
  --format <format>         Output format: text, json (default: text)
  --flat                    List flattened objects (for tree backups)
  --deps                    Show dependencies (tree structure only)
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
    '  tree      Fetch package hierarchy and dependencies (no source)',
    '  enrich    Populate tree file with metadata and source',
    '  backup    Backup ABAP objects or packages (one-step)',
    '  plan      Prepare restoration sequence (offline)',
    '  verify    Update plan with target system state (online)',
    '  check     Check backup against target system (online)',
    '  restore   Execute restoration plan on target system (online)',
    '  activate  Activate existing objects in target system',
    '  diff      Compare backup with target system',
    '  validate  Validate backup checksums',
    '  list      List backup contents',
    '',
    'Run "adt-backup <command> --help" for command-specific options.',
    '',
    commonOptions,
  ].join('\n');
}
