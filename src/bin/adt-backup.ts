#!/usr/bin/env node

import { run } from '../lib/run';

run().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
