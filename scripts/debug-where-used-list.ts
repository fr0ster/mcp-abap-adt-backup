
import { AdtClient } from '@mcp-abap-adt/adt-clients';
import { createAbapConnection } from '@mcp-abap-adt/connection';
import { getSapConfigFromBroker } from '../src/lib/auth/getSapConfigFromBroker';
import { createLogger } from '../src/lib/cli/createLogger';

async function run() {
  const args = process.argv.slice(2);
  const objectName = args[0];
  const objectType = args[1]; // e.g. 'DTEL/DE' or 'class'
  const destination = args[2];

  if (!objectName || !objectType || !destination) {
    console.error('Usage: npx ts-node scripts/debug-where-used-list.ts <NAME> <TYPE> <DESTINATION>');
    console.error('Example: npx ts-node scripts/debug-where-used-list.ts ZMY_TABLE TABL/DT MY_SYSTEM');
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

  console.log(`Checking dependencies for ${objectName} (${objectType}) using getWhereUsedList...`);

  try {
    const result = await client.getUtils().getWhereUsedList({
      object_name: objectName,
      object_type: objectType,
      enableAllTypes: true,
      includeRawXml: true
    });

    console.log('\n--- Result Summary ---');
    console.log(`Object: ${result.objectName} (${result.objectType})`);
    console.log(`Description: ${result.resultDescription}`);
    console.log(`Total References Found: ${result.totalReferences}`);

    if (result.references.length > 0) {
      console.log('\n--- References ---');
      result.references.forEach((ref, index) => {
        console.log(`${index + 1}. [${ref.type}] ${ref.name}`);
        console.log(`   URI: ${ref.uri}`);
        console.log(`   Package: ${ref.packageName || 'N/A'}`);
        if (ref.parentUri) console.log(`   Parent URI: ${ref.parentUri}`);
        console.log('');
      });
    } else {
      console.log('\nNo references found.');
    }

    if (result.rawXml) {
      console.log('\n--- Raw XML (First 1000 chars) ---');
      console.log(result.rawXml.substring(0, 1000) + '...');
    }

  } catch (error: any) {
    console.error('\nERROR:', error.message);
    if (error.response) {
      console.error('Status:', error.response.status);
      console.error('Data:', error.response.data);
    }
  }
}

run().catch(console.error);
