#!/bin/bash
# scripts/query_azure_infra.sh

OUTPUT_DIR="output"
mkdir -p $OUTPUT_DIR

echo "[]" > $OUTPUT_DIR/azure.json

# --- Storage Accounts ---
echo "Querying storage accounts..."
accounts_json=$(az storage account list --query "[].{id:id, name:name, resourceGroup:resourceGroup}" -o json)

echo "$accounts_json" | jq -c '.[]' | while read account; do
    name=$(echo "$account" | jq -r '.name')
    rg=$(echo "$account" | jq -r '.resourceGroup')
    id=$(echo "$account" | jq -r '.id')

    account_details=$(az storage account show --name "$name" --resource-group "$rg" -o json)
    blob_service_details=$(az storage account blob-service-properties show --account-name "$name" --resource-group "$rg" -o json)
    file_service_details=$(az storage account file-service-properties show --account-name "$name" --resource-group "$rg" -o json)

    combined=$(jq -n \
      --argjson acc "$account_details" \
      --argjson blob "$blob_service_details" \
      --argjson file "$file_service_details" \
      '{type:"storage", account:$acc, blobService:$blob, fileService:$file}')

    jq --argjson details "$combined" '. += [$details]' $OUTPUT_DIR/azure.json > tmp.$$.json && mv tmp.$$.json $OUTPUT_DIR/azure.json
done

# --- Virtual Machines ---
echo "Querying virtual machines..."
vms=$(az vm list -d -o json)
jq --argjson vms "$vms" '. += [{"type":"vm","vms":$vms}]' $OUTPUT_DIR/azure.json > tmp.$$.json && mv tmp.$$.json $OUTPUT_DIR/azure.json

# --- Identity & Access Management (IAM) ---
echo "Querying IAM roles and users..."
roles=$(az role assignment list -o json)
users=$(az ad user list -o json)
jq --argjson roles "$roles" --argjson users "$users" '. += [{"type":"iam","roles":$roles,"users":$users}]' $OUTPUT_DIR/azure.json > tmp.$$.json && mv tmp.$$.json $OUTPUT_DIR/azure.json

# --- Databases (SQL Servers & Databases) ---
echo "Querying Azure SQL databases..."
dbs=$(az sql db list --ids $(az sql server list --query "[].id" -o tsv) -o json)
jq --argjson dbs "$dbs" '. += [{"type":"db","databases":$dbs}]' $OUTPUT_DIR/azure.json > tmp.$$.json && mv tmp.$$.json $OUTPUT_DIR/azure.json

echo "PCI DSS data collection complete -> $OUTPUT_DIR/azure.json"
