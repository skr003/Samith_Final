# scripts/generate_remediation_manual.py
import json

def main():
    try:
        with open('drift_report.json', 'r') as f:
            report = json.load(f)
    except FileNotFoundError:
        report = []

    with open('remediate.sh', 'w') as f:
        f.write("#!/bin/bash\n")
        f.write("# Auto-generated CIS remediation script for Azure Storage\n")
        f.write("set -e\n\n")

        if not report:
            f.write("echo '✅ No storage drift detected.'\n")
            return

        for item in report:
            rule_id, resource_id, command = item.get('ruleId'), item.get('resourceId'), ""
            
            # --- Remediation Mapping for Storage (Section 10) ---
            if rule_id == "CIS-10.3.1.3":
                command = f"az storage account update --ids \"{resource_id}\" --allow-shared-key-access false"
            elif rule_id == "CIS-10.3.2.2":
                command = f"az storage account update --ids \"{resource_id}\" --public-network-access Disabled"
            elif rule_id == "CIS-10.3.2.3":
                command = f"az storage account update --ids \"{resource_id}\" --default-action Deny"
            elif rule_id == "CIS-10.3.3.1":
                command = f"az storage account update --ids \"{resource_id}\" --default-to-oauth-authentication true"
            elif rule_id == "CIS-10.3.4":
                command = f"az storage account update --ids \"{resource_id}\" --https-only true"
            elif rule_id == "CIS-10.3.5":
                command = f"az storage account update --ids \"{resource_id}\" --bypass AzureServices"
            elif rule_id == "CIS-10.3.7":
                command = f"az storage account update --ids \"{resource_id}\" --min-tls-version TLS1_2"
            elif rule_id == "CIS-10.3.8":
                command = f"az storage account update --ids \"{resource_id}\" --allow-cross-tenant-replication false"
            elif rule_id == "CIS-10.3.9":
                command = f"az storage account update --ids \"{resource_id}\" --allow-blob-public-access false"
            elif rule_id == "CIS-10.3.12":
                command = f"az storage account update --ids \"{resource_id}\" --sku Standard_GRS"
            elif rule_id == "CIS-10.2.1":
                command = f"az storage account blob-service-properties update --account-name $(az resource show --ids \"{resource_id}\" --query name -o tsv) -g $(az resource show --ids \"{resource_id}\" --query resourceGroup -o tsv) --enable-delete-retention true --delete-retention-days 90"
            elif rule_id == "CIS-10.2.2":
                command = f"az storage account blob-service-properties update --account-name $(az resource show --ids \"{resource_id}\" --query name -o tsv) -g $(az resource show --ids \"{resource_id}\" --query resourceGroup -o tsv) --enable-versioning true"
            elif rule_id == "CIS-10.3.6-Container":
                command = f"az storage account blob-service-properties update --account-name $(az resource show --ids \"{resource_id}\" --query name -o tsv) -g $(az resource show --ids \"{resource_id}\" --query resourceGroup -o tsv) --enable-container-delete-retention true --container-delete-retention-days 90"
            elif rule_id == "CIS-10.1.1":
                command = f"az storage account file-service-properties update --account-name $(az resource show --ids \"{resource_id}\" --query name -o tsv) -g $(az resource show --ids \"{resource_id}\" --query resourceGroup -o tsv) --enable-delete-retention true --delete-retention-days 7"
            elif rule_id == "CIS-10.1.2":
                command = f"az storage account file-service-properties update --account-name $(az resource show --ids \"{resource_id}\" --query name -o tsv) -g $(az resource show --ids \"{resource_id}\" --query resourceGroup -o tsv) --versions SMB3.1.1"
            elif rule_id == "CIS-10.1.3":
                 command = f"az storage account file-service-properties update --account-name $(az resource show --ids \"{resource_id}\" --query name -o tsv) -g $(az resource show --ids \"{resource_id}\" --query resourceGroup -o tsv) --channel-encryption AES-256-GCM"

            if command:
                f.write(f"# Remediating: {item.get('description')}\n")
                f.write(f"{command}\n\n")

    print("Remediation script 'remediate.sh' generated for Storage Services.")

if __name__ == "__main__":
    main()
