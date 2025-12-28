import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import YAML from 'yaml';

const rootDir = process.cwd();
const configPath = path.join(rootDir, 'tests', 'test-config.yaml');

if (!fs.existsSync(configPath)) {
  console.error(
    `Missing config: ${configPath}\nCopy tests/test-config.yaml.template and fill in values.`,
  );
  process.exit(1);
}

const config = YAML.parse(fs.readFileSync(configPath, 'utf8'));

const destination = config?.auth_broker?.abap?.destination || '';
const destinationDir = config?.auth_broker?.destination_dir || '';
const environmentFile = config?.auth_broker?.environment_file || '';
const outputDir = config?.tests?.backup?.output_dir || '';
const packageName = config?.tests?.backup?.package?.name || '';
const className = config?.tests?.backup?.class?.name || '';

const missing = [];
if (!packageName) missing.push('tests.backup.package.name');
if (!className) missing.push('tests.backup.class.name');
if (!outputDir) missing.push('tests.backup.output_dir');
if (!destination) missing.push('auth_broker.abap.destination');
if (!environmentFile && !destinationDir) {
  missing.push('auth_broker.destination_dir or auth_broker.environment_file');
}
if (missing.length > 0) {
  console.error(`Missing config values: ${missing.join(', ')}`);
  process.exit(1);
}

fs.mkdirSync(outputDir, { recursive: true });

const cliPath = path.join(rootDir, 'dist', 'bin', 'adt-backup.js');
if (!fs.existsSync(cliPath)) {
  console.error(
    `Missing CLI build: ${cliPath}\nRun \"npm run build\" before integration tests.`,
  );
  process.exit(1);
}

const baseArgs = ['--destination', destination];
const envArgs = environmentFile ? ['--env', environmentFile] : [];
const authRootArgs = environmentFile ? [] : ['--auth-root', destinationDir];

const run = (args) => {
  const result = spawnSync(
    'node',
    [cliPath, ...args, ...baseArgs, ...envArgs, ...authRootArgs],
    {
    stdio: 'inherit',
    },
  );
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
};

const packageBackup = path.join(
  outputDir,
  `${packageName}_backup.yaml`,
);
const classBackup = path.join(outputDir, `${className}_backup.yaml`);
const classSource = path.join(outputDir, `${className}.abap`);

run(['backup', '--package', packageName, '--output', packageBackup]);
run(['validate', '--input', packageBackup]);
run(['list', '--input', packageBackup]);
run(['verify', '--input', packageBackup]);

run(['backup', '--objects', `class:${className}`, '--output', classBackup]);
run(['validate', '--input', classBackup]);
run(['verify', '--input', classBackup]);
run(['extract', '--input', classBackup, '--object', `class:${className}`, '--out', classSource]);

console.log('Integration tests completed');
