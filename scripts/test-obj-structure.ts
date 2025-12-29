
import { createTokenProvider } from '../src/lib/auth/createTokenProvider';
import { AdtClient } from '@mcp-abap-adt/adt-clients';
import { createAbapConnection } from '@mcp-abap-adt/connection';
import { getSapConfigFromBroker } from '../src/lib/auth/getSapConfigFromBroker';
import { createLogger } from '../src/lib/cli/createLogger';

async function run() {
  const args = process.argv.slice(2);
  const packageName = args[0];
  const destination = args[1];

  const logger = createLogger(0);
  const { config, tokenRefresher } = await getSapConfigFromBroker({ destination, logger });
  const connection = createAbapConnection(config, undefined, undefined, tokenRefresher);
  const client = new AdtClient(connection);
  
  console.log(`Fetching object structure for ${packageName}...`);
  try {
    const response = await client.getUtils().getObjectStructure('DEVC/K', packageName.toUpperCase());
    console.log(JSON.stringify(response.data, null, 2));
  } catch (error: any) {
    console.error('Error:', error.message);
  }
}

run().catch(console.error);
