#!/bin/bash
# scripts/query_azure_infra.sh

OUTPUT_DIR="output"
mkdir -p $OUTPUT_DIR

#echo "Logging in to Azure with Service Principal..."
#az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET --tenant $AZURE_TENANT_ID > /dev/null
#az login --service-principal --username "$AZURE_CLIENT_ID" --password "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID"

echo "Querying all storage accounts..."
# Get a list of storage account IDs and resource groups
accounts_json=$(az storage account list --query "[].{id:id, name:name, resourceGroup:resourceGroup}" -o json)

# Initialize a JSON array
echo "[]" > $OUTPUT_DIR/azure.json

# Loop through each storage account to get detailed properties
echo "$accounts_json" | jq -c '.[]' | while read account; do
    name=$(echo "$account" | jq -r '.name')
    rg=$(echo "$account" | jq -r '.resourceGroup')
    id=$(echo "$account" | jq -r '.id')
    
    echo "Fetching details for storage account: $name in RG: $rg..."
    
    # Get main account properties, blob service properties, and file service properties
    account_details=$(az storage account show --name "$name" --resource-group "$rg" -o json)
    blob_service_details=$(az storage account blob-service-properties show --account-name "$name" --resource-group "$rg" -o json)
    file_service_details=$(az storage account file-service-properties show --account-name "$name" --resource-group "$rg" -o json)
    
    # Combine all details into a single JSON object for this account
    combined_details=$(jq -n \
      --argjson acc "$account_details" \
      --argjson blob "$blob_service_details" \
      --argjson file "$file_service_details" \
      '{account: $acc, blobService: $blob, fileService: $file}')
      
    # Append the combined details to our master JSON file
    jq --argjson details "$combined_details" '. += [$details]' $OUTPUT_DIR/azure.json > tmp.$$.json && mv tmp.$$.json $OUTPUT_DIR/azure.json
done

echo "Comprehensive data collection for storage complete. File 'azure.json' is ready."
