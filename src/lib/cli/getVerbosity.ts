export function getVerbosity(argv: string[]): number {
  let level = 0;
  for (const arg of argv) {
    if (arg === '-v') {
      level = Math.max(level, 1);
    }
    if (arg === '-vv') {
      level = Math.max(level, 2);
    }
    if (arg === '-vvv') {
      level = Math.max(level, 3);
    }
    if (arg.startsWith('--verbose=')) {
      const value = Number(arg.split('=')[1]);
      if (!Number.isNaN(value)) {
        level = Math.max(level, value);
      }
    }
    if (arg === '--verbose') {
      level = Math.max(level, 2);
    }
  }
  return level;
}
