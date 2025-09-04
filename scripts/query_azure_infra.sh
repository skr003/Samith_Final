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

# Collect VM details with instance view (includes patch state)
vms=()
for rg in $(az group list --query "[].name" -o tsv); do
  for vm in $(az vm list -g $rg --query "[].name" -o tsv); do
    echo "Running patch assessment for VM: $vm in RG: $rg"
    az vm assess-patches -g $rg -n $vm >/dev/null

    # Fetch instance view with patch status after assessment
    details=$(az vm get-instance-view -g $rg -n $vm \
      --query "{id:id,name:name,resourceGroup:resourceGroup,osProfile:osProfile,instanceView:instanceView}" -o json)

    vms+=("$details")
  done
done

# Merge into azure.json
printf '%s\n' "${vms[@]}" | jq -s '.' > tmp_vms.json
jq --slurpfile vms tmp_vms.json '. += [{"type":"vm","vms":$vms}]' $OUTPUT_DIR/azure.json > tmp.$$.json && mv tmp.$$.json $OUTPUT_DIR/azure.json

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
