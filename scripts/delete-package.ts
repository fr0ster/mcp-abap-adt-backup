
import * as readline from 'node:readline';
import { AdtClient, type ObjectReference } from '@mcp-abap-adt/adt-clients';
import { createAbapConnection } from '@mcp-abap-adt/connection';
import { getSapConfigFromBroker } from '../src/lib/auth/getSapConfigFromBroker';
import { createLogger } from '../src/lib/cli/createLogger';
import { mapAdtTypeToSupported } from '../src/lib/tree/mapAdtTypeToSupported';
import { typeOrder } from '../src/lib/constants/typeOrder';

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
    
    // Create priority map for deletion (reverse creation order)
    // Higher index in typeOrder = created later = delete earlier
    // So we sort descending by index
    const priority = new Map(typeOrder.map((type, index) => [type, index]));

    const objectsToDelete: ObjectReference[] = allNodes
      .filter(n => n.adtType && n.name)
      .map(n => ({
        type: n.adtType!,
        name: n.name,
      }))
      .sort((a, b) => {
        const typeA = mapAdtTypeToSupported(a.type);
        const typeB = mapAdtTypeToSupported(b.type);
        
        // If types are unknown, put them at the beginning (safest assumption? or end?)
        // typeOrder contains known types.
        const orderA = typeA ? (priority.get(typeA) ?? -1) : -1;
        const orderB = typeB ? (priority.get(typeB) ?? -1) : -1;

        // Descending order of index (delete "higher" types first)
        // e.g. Class (idx 10) before Package (idx 0)
        return orderB - orderA; 
      });

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
    const checkResponse = await client.getUtils().checkDeletionGroup(objectsToDelete);
    const messages = checkResponse.data?.messages || [];
    const errors = messages.filter((m: any) => m.severity === 'error' || m.severity === 'E');

    if (errors.length > 0) {
      console.error('\nCANNOT DELETE: Deletion check failed with errors:');
      errors.forEach((e: any) => console.error(` - [${e.objName}] ${e.text}`));
      process.exit(1);
    }
    
    const warnings = messages.filter((m: any) => m.severity === 'warning' || m.severity === 'W');
    if (warnings.length > 0) {
      console.warn('\nCheck warnings:');
      warnings.forEach((w: any) => console.warn(` - [${w.objName}] ${w.text}`));
      const proceed = await confirm('Proceed despite warnings?');
      if (!proceed) {
        console.log('Aborted.');
        process.exit(0);
      }
    } else {
      console.log('Check passed.');
    }

    console.log('Deleting objects sequentially...');
    for (const obj of objectsToDelete) {
        process.stdout.write(`Deleting ${obj.type} ${obj.name}... `);
        try {
            // We use deleteObjectsGroup for single object as well, or we can look for individual delete method.
            // But deleteObjectsGroup takes an array, so passing [obj] is fine.
            await client.getUtils().deleteObjectsGroup([obj], transportRequest);
            console.log('OK');
        } catch (error: any) {
            console.log('FAILED');
            console.error(`  Error deleting ${obj.name}: ${error.message}`);
             if (error.response) {
                 console.error('  Status:', error.response.status);
             }
        }
    }
    console.log('Deletion process finished.');

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
