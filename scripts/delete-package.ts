import * as readline from 'node:readline';
import { AdtClient } from '@mcp-abap-adt/adt-clients';
import { analyseDeletion } from '@mcp-abap-adt/adt-strategies';
import type { IObjectReference } from '@mcp-abap-adt/interfaces-adt';
import { describeFailure } from '../src/lib/adt/answer';
import { getSapConfigFromBroker } from '../src/lib/auth/getSapConfigFromBroker';
import { createLogger } from '../src/lib/cli/createLogger';
import {
  closeConnection,
  createConnection,
  resolveSystemType,
} from '../src/lib/connection/createConnection';
import { typeOrder } from '../src/lib/constants/typeOrder';
import { objectReference } from '../src/lib/restore/objectReference';
import { flattenTree } from '../src/lib/tree/flattenTree';
import { mapAdtTypeToSupported } from '../src/lib/tree/mapAdtTypeToSupported';
import { walkPackageTree } from '../src/lib/tree/walkPackage';

async function confirm(message: string): Promise<boolean> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise((resolve) => {
    rl.question(`${message} (y/N): `, (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase() === 'y');
    });
  });
}

async function run(): Promise<void> {
  const [packageName, destination, transportRequest, systemTypeArg] =
    process.argv.slice(2);
  if (!packageName || !destination) {
    console.error(
      'Usage: npx ts-node scripts/delete-package.ts <PACKAGE> <DESTINATION> [TRANSPORT_REQUEST] [cloud|onprem|legacy]',
    );
    process.exit(1);
  }

  const logger = createLogger(0);
  const { config, tokenRefresher } = await getSapConfigFromBroker({
    destination,
    logger,
  });
  const connection = createConnection(
    config,
    resolveSystemType(systemTypeArg),
    tokenRefresher,
  );
  await connection.connect();
  try {
    const client = new AdtClient(connection);
    console.log(`Fetching hierarchy for package ${packageName}...`);
    const root = await walkPackageTree(client, packageName);

    // Delete in reverse creation order: a type created later goes first.
    const priority = new Map(typeOrder.map((type, index) => [type, index]));
    const orderOf = (type: string): number => {
      const supported = mapAdtTypeToSupported(type);
      return supported ? (priority.get(supported) ?? -1) : -1;
    };
    // Only what this tool restores: a walk also lists what the system
    // generated for a published binding (G4BA, SCO2, SUSH), which has no ADT
    // address — a deletion check over it refuses the whole group — and goes
    // with its binding.
    const objects: IObjectReference[] = flattenTree(root)
      .filter(
        (n) =>
          n.adtType && n.name && mapAdtTypeToSupported(n.adtType) !== undefined,
      )
      .map((n) =>
        objectReference({
          name: n.name,
          adtType: n.adtType as string,
          functionGroupName: n.functionGroupName,
        }),
      )
      .sort((a, b) => orderOf(b.type) - orderOf(a.type));

    if (objects.length === 0) {
      console.log('No objects found to delete.');
      return;
    }
    console.log(`\nFound ${objects.length} objects to delete:`);
    for (const o of objects) console.log(` - [${o.type}] ${o.name}`);
    if (transportRequest) {
      console.log(`\nUsing Transport Request: ${transportRequest}`);
    }

    const confirmed = await confirm(
      '\nAre you sure you want to PERMANENTLY DELETE these objects?',
    );
    if (!confirmed) {
      console.log('Aborted.');
      return;
    }

    const utils = client.getUtils();
    console.log('Checking deletion...');
    const checked = await utils.checkDeletionGroup(objects, {
      analyse: analyseDeletion,
    });
    if (!checked.ok) {
      console.error(`\nCANNOT DELETE: ${describeFailure(checked.getError())}`);
      process.exitCode = 1;
      return;
    }
    console.log('Check passed.');

    console.log('Deleting objects sequentially...');
    for (const obj of objects) {
      const deleted = await utils.deleteObjectsGroup([obj], transportRequest, {
        analyse: analyseDeletion,
      });
      console.log(
        deleted.ok
          ? `Deleted ${obj.type} ${obj.name}`
          : `FAILED ${obj.type} ${obj.name}: ${describeFailure(deleted.getError())}`,
      );
    }
    console.log('Deletion process finished.');
  } finally {
    await closeConnection(connection);
  }
}

run().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
