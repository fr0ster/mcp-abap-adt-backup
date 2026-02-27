export function parseArgs(
  argv: string[],
): Record<string, string | boolean | number> {
  const args: Record<string, string | boolean | number> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (!next || next.startsWith('--') || next.startsWith('-')) {
        args[key] = true;
      } else {
        args[key] = next;
        i += 1;
      }
    } else if (arg.startsWith('-')) {
      // Handle short flags like -v, -vv, -vvv
      const key = arg.slice(1);
      if (key.startsWith('v')) {
        const vCount = key.split('').filter((c) => c === 'v').length;
        args.verbosity = Math.max(Number(args.verbosity || 0), vCount);
      } else {
        args[key] = true;
      }
    }
  }
  return args;
}
