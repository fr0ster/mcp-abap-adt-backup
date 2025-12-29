
import { createTokenProvider } from '../src/lib/auth/createTokenProvider';
import { AdtClient } from '@mcp-abap-adt/adt-clients';
import { createAbapConnection } from '@mcp-abap-adt/connection';
import { getSapConfigFromBroker } from '../src/lib/auth/getSapConfigFromBroker';
import { createLogger } from '../src/lib/cli/createLogger';

async function run() {
  const args = process.argv.slice(2);
  const packageName = args[0];
  const destination = args[1];

  if (!packageName || !destination) {
    console.error('Usage: ts-node scripts/debug-nodestructure.ts <package> <destination>');
    process.exit(1);
  }

  const logger = createLogger(0);
  const { config, tokenRefresher } = await getSapConfigFromBroker({ destination, logger });
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
  
  console.log(`Fetching node structure for ${packageName}...`);
  try {
    const response = await client.getUtils().fetchNodeStructure('DEVC/K', packageName.toUpperCase());
    
    console.log('Success:', response.status);
    console.log(typeof response.data === 'string' ? response.data : JSON.stringify(response.data, null, 2));
  } catch (error: any) {
    console.error('Error:', error.message);
    if (error.response) {
      console.error('Status:', error.response.status);
      console.error('Data:', error.response.data);
    }
  }
}

run().catch(console.error);
