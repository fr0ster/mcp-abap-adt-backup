
import * as readline from 'node:readline';
import { AdtClient, type ObjectReference } from '@mcp-abap-adt/adt-clients';
import { createAbapConnection } from '@mcp-abap-adt/connection';
import { getSapConfigFromBroker } from '../src/lib/auth/getSapConfigFromBroker';
import { createLogger } from '../src/lib/cli/createLogger';

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

function flattenHierarchy(node: any, list: any[] = []) {
  if (node.children) {
    for (const child of node.children) {
      flattenHierarchy(child, list);
    }
  }
  // Post-order traversal: children first, then parent
  list.push(node);
  return list;
}

async function run() {
  const args = process.argv.slice(2);
  const packageName = args[0];
  const destination = args[1];
  const transportRequest = args[2];

  if (!packageName || !destination) {
    console.error('Usage: npx ts-node scripts/delete-package.ts <PACKAGE> <DESTINATION> [TRANSPORT_REQUEST]');
    process.exit(1);
  }

  const logger = createLogger(0);
  const { config, tokenRefresher } = await getSapConfigFromBroker({
    destination,
    logger,
  });

  if (!config) {
    console.error(`Destination ${destination} not found`);
    process.exit(1);
  }

  const connection = createAbapConnection(
    config,
    undefined,
    undefined,
    tokenRefresher,
  );
  const client = new AdtClient(connection);

  console.log(`Fetching hierarchy for package ${packageName}...`);
  try {
    const hierarchy = await client.getUtils().getPackageHierarchy(packageName.toUpperCase());
    
    // Flatten hierarchy using post-order traversal (children first)
    const allNodes = flattenHierarchy(hierarchy);
    
    // Filter out objects that don't have an adtType (root node might if it's just a container, but usually it's the package itself)
    // We also want to delete the package itself, which should be the last item in post-order list if getPackageHierarchy returns it as root
    const objectsToDelete: ObjectReference[] = allNodes
      .filter(n => n.adtType && n.name)
      .map(n => ({
        type: n.adtType!,
        name: n.name,
      }));

    if (objectsToDelete.length === 0) {
      console.log('No objects found to delete.');
      return;
    }

    console.log(`
Found ${objectsToDelete.length} objects to delete:`);
    objectsToDelete.forEach(o => console.log(` - [${o.type}] ${o.name}`));

    if (transportRequest) {
      console.log(`
Using Transport Request: ${transportRequest}`);
    }

    const confirmed = await confirm('\nAre you sure you want to PERMANENTLY DELETE these objects?');
    if (!confirmed) {
      console.log('Aborted.');
      process.exit(0);
    }

    console.log('Checking deletion...');
    // Optional: Check deletion first
    await client.getUtils().checkDeletionGroup(objectsToDelete);
    console.log('Check passed. Deleting...');

    await client.getUtils().deleteObjectsGroup(objectsToDelete, transportRequest);
    console.log('Successfully deleted objects.');

  } catch (error: any) {
    console.error('Error:', error.message);
    if (error.response) {
      console.error('Status:', error.response.status);
      console.error('Data:', JSON.stringify(error.response.data, null, 2));
    }
    process.exit(1);
  }
}

run().catch(console.error);
