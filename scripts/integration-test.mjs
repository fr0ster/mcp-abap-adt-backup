import fs from 'node:fs';
import os from 'node:os';
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

const backupAuth = config?.auth_broker?.backup || {};
const verifyAuth = config?.auth_broker?.verify || {};
const restoreAuth = config?.auth_broker?.restore || {};
const destination = backupAuth?.abap?.destination || '';
const destinationDir = backupAuth?.destination_dir || '';
const environmentFile = backupAuth?.environment_file || '';
const verifyDestination = verifyAuth?.abap?.destination || destination || '';
const verifyDestinationDir = verifyAuth?.destination_dir || destinationDir || '';
const verifyEnvironmentFile =
  verifyAuth?.environment_file || environmentFile || '';
const restoreDestination =
  restoreAuth?.abap?.destination || verifyDestination || destination || '';
const restoreDestinationDir =
  restoreAuth?.destination_dir || verifyDestinationDir || destinationDir || '';
const restoreEnvironmentFile =
  restoreAuth?.environment_file || verifyEnvironmentFile || environmentFile || '';
const outputDir = config?.tests?.backup?.output_dir || '';
const packageName = config?.tests?.backup?.package?.name || '';
const className = config?.tests?.backup?.class?.name || '';
const restoreEnabled = Boolean(config?.tests?.restore?.enabled);
const restoreForce = Boolean(config?.tests?.restore?.force);
const verifyEnabled = Boolean(config?.tests?.verify?.enabled);
const verifyStrict = Boolean(config?.tests?.verify?.strict);

const missing = [];
if (!packageName) missing.push('tests.backup.package.name');
if (!className) missing.push('tests.backup.class.name');
if (!outputDir) missing.push('tests.backup.output_dir');
if (!environmentFile && !destination) {
  missing.push('auth_broker.backup.abap.destination');
}
if (!environmentFile && !destinationDir) {
  // Will fall back to defaults based on OS.
}
if (!verifyEnvironmentFile && !verifyDestination) {
  missing.push('auth_broker.verify.abap.destination');
}
if (restoreEnabled && !restoreEnvironmentFile && !restoreDestination) {
  missing.push('auth_broker.restore.abap.destination');
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

const baseArgs = destination ? ['--destination', destination] : [];
const envArgs = environmentFile ? ['--env', environmentFile] : [];
const defaultDestinationDir =
  process.platform === 'win32'
    ? path.join(os.homedir(), 'Documents', 'mcp-abap-adt')
    : path.join(os.homedir(), '.config', 'mcp-abap-adt');
const resolvedDestinationDir = destinationDir || defaultDestinationDir;
const authRootArgs = environmentFile
  ? []
  : ['--auth-root', resolvedDestinationDir];
if (environmentFile) {
  console.log(`Using backup environment_file: ${environmentFile}`);
} else {
  console.log(`Using backup destination_dir: ${resolvedDestinationDir}`);
}

const verifyBaseArgs = verifyDestination
  ? ['--destination', verifyDestination]
  : [];
const verifyEnvArgs = verifyEnvironmentFile
  ? ['--env', verifyEnvironmentFile]
  : [];
const resolvedVerifyDestinationDir =
  verifyDestinationDir || defaultDestinationDir;
const verifyAuthRootArgs = verifyEnvironmentFile
  ? []
  : ['--auth-root', resolvedVerifyDestinationDir];
if (verifyEnvironmentFile) {
  console.log(`Using verify environment_file: ${verifyEnvironmentFile}`);
} else {
  console.log(`Using verify destination_dir: ${resolvedVerifyDestinationDir}`);
}

const restoreBaseArgs = restoreDestination
  ? ['--destination', restoreDestination]
  : [];
const restoreEnvArgs = restoreEnvironmentFile
  ? ['--env', restoreEnvironmentFile]
  : [];
const resolvedRestoreDestinationDir =
  restoreDestinationDir || defaultDestinationDir;
const restoreAuthRootArgs = restoreEnvironmentFile
  ? []
  : ['--auth-root', resolvedRestoreDestinationDir];
if (restoreEnvironmentFile) {
  console.log(`Using restore environment_file: ${restoreEnvironmentFile}`);
} else {
  console.log(`Using restore destination_dir: ${resolvedRestoreDestinationDir}`);
}

const run = (args, extraArgs = []) => {
  const result = spawnSync(
    'node',
    [cliPath, ...args, ...baseArgs, ...envArgs, ...authRootArgs, ...extraArgs],
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
if (verifyEnabled) {
  const verifyArgs = ['verify', '--input', packageBackup];
  if (verifyStrict) {
    verifyArgs.push('--strict');
  }
  run(verifyArgs, [...verifyBaseArgs, ...verifyEnvArgs, ...verifyAuthRootArgs]);
}

run(['backup', '--objects', `class:${className}`, '--output', classBackup]);
run(['validate', '--input', classBackup]);
if (verifyEnabled) {
  const verifyArgs = ['verify', '--input', classBackup];
  if (verifyStrict) {
    verifyArgs.push('--strict');
  }
  run(verifyArgs, [...verifyBaseArgs, ...verifyEnvArgs, ...verifyAuthRootArgs]);
}
run([
  'extract',
  '--input',
  classBackup,
  '--object',
  `class:${className}`,
  '--out',
  classSource,
]);

if (restoreEnabled) {
  const restoreArgs = ['restore', '--input', packageBackup];
  if (restoreForce) {
    restoreArgs.push('--force');
  }
  run(
    restoreArgs,
    [...restoreBaseArgs, ...restoreEnvArgs, ...restoreAuthRootArgs],
  );
}

console.log('Integration tests completed');
