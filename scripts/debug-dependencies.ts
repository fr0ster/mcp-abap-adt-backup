
import { AdtClient } from '@mcp-abap-adt/adt-clients';
import { createAbapConnection } from '@mcp-abap-adt/connection';
import { getSapConfigFromBroker } from '../src/lib/auth/getSapConfigFromBroker';
import { createLogger } from '../src/lib/cli/createLogger';
import { responseToText } from '../src/lib/utils/responseToText';

async function run() {
  const args = process.argv.slice(2);
  const objectName = args[0];
  const objectType = args[1]; // e.g. 'DTEL/DE' or 'class'
  const destination = args[2];

  if (!objectName || !objectType || !destination) {
    console.error('Usage: npx ts-node scripts/debug-dependencies.ts <NAME> <TYPE> <DESTINATION>');
    console.error('Example: npx ts-node scripts/debug-dependencies.ts ZMY_TABLE TABL/DT MY_SYSTEM');
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

  console.log(`Checking dependencies for ${objectName} (${objectType})...`);

  try {
    // Step 1: Get Scope
    console.log('\n--- Step 1: Fetching Scope ---');
    const scopeResponse = await client.getUtils().getWhereUsedScope({
      object_name: objectName,
      object_type: objectType,
    });
    const scopeXml = responseToText(scopeResponse);
    console.log('Scope XML (partial):');
    console.log(scopeXml.substring(0, 500) + '...');

    // Step 2: Enable All Types
    console.log('\n--- Step 2: Enabling All Types in Scope ---');
    const enabledScope = client.getUtils().modifyWhereUsedScope(scopeXml, { enableAll: true });
    // Show a snippet of modification
    console.log('Modified Scope XML (partial snippet):');
    const snippetIndex = enabledScope.indexOf('isSelected="true"');
    console.log(enabledScope.substring(Math.max(0, snippetIndex - 50), snippetIndex + 50) + '...');

    // Step 3: Get Usage References
    console.log('\n--- Step 3: Fetching Usage References ---');
    const response = await client.getUtils().getWhereUsed({
      object_name: objectName,
      object_type: objectType,
      scopeXml: enabledScope,
    });
    
    const resultXml = responseToText(response);
    console.log('Result XML:');
    console.log(resultXml);

  } catch (error: any) {
    console.error('\nERROR:', error.message);
    if (error.response) {
      console.error('Status:', error.response.status);
      console.error('Data:', error.response.data);
    }
  }
}

run().catch(console.error);
