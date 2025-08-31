# scripts/analyze_drift_manual.py
import json

def analyze_storage_accounts():
    """
    Manually checks storage accounts against CIS v4.0.0 Section 10 controls.
    This version includes robust checks for None/null values from the Azure API.
    """
    try:
        with open('output/azure.json', 'r') as f:
            all_storage_data = json.load(f)
    except FileNotFoundError:
        return []

    violations = []

    for storage_data in all_storage_data:
        acc = storage_data.get('account', {})
        blob_svc = storage_data.get('blobService', {})
        file_svc = storage_data.get('fileService', {})
        
        # Skip if essential data is missing
        if not all([acc, blob_svc, file_svc]):
            continue

        resource_id = acc.get('id')
        if not resource_id:
            continue

        # --- 10.3 Storage Account General Checks ---
        if acc.get('allowSharedKeyAccess', True):
            violations.append({"resourceId": resource_id, "ruleId": "CIS-10.3.1.3", "description": "Storage Account: 'Allow storage account key access' should be 'Disabled'."})
        
        if acc.get('publicNetworkAccess') != 'Disabled':
            violations.append({"resourceId": resource_id, "ruleId": "CIS-10.3.2.2", "description": "Storage Account: 'Public Network Access' should be 'Disabled'."})
        
        network_acls = acc.get('networkAcls') or {}
        if network_acls.get('defaultAction') != 'Deny':
            violations.append({"resourceId": resource_id, "ruleId": "CIS-10.3.2.3", "description": "Storage Account: Default network access rule should be 'Deny'."})
        
        if not acc.get('defaultToOAuthAuthentication', False):
            violations.append({"resourceId": resource_id, "ruleId": "CIS-10.3.3.1", "description": "Storage Account: 'Default to Microsoft Entra authorization' should be 'Enabled'."})
        
        if not acc.get('supportsHttpsTrafficOnly', False):
            violations.append({"resourceId": resource_id, "ruleId": "CIS-10.3.4", "description": "Storage Account: 'Secure transfer required' should be 'Enabled'."})
        
        if "AzureServices" not in (network_acls.get('bypass') or ''):
             violations.append({"resourceId": resource_id, "ruleId": "CIS-10.3.5", "description": "Storage Account: 'Allow trusted Microsoft services' should be enabled if network rules are set."})
        
        if acc.get('minimumTlsVersion') != 'TLS1_2':
            violations.append({"resourceId": resource_id, "ruleId": "CIS-10.3.7", "description": "Storage Account: Minimum TLS version should be '1.2'."})
        
        if acc.get('allowCrossTenantReplication', True):
            violations.append({"resourceId": resource_id, "ruleId": "CIS-10.3.8", "description": "Storage Account: 'Cross Tenant Replication' should not be enabled."})
        
        if acc.get('allowBlobPublicAccess', True):
            violations.append({"resourceId": resource_id, "ruleId": "CIS-10.3.9", "description": "Storage Account: 'Allow Blob Anonymous Access' should be 'Disabled'."})
        
        sku = acc.get('sku') or {}
        if sku.get('name') not in ['Standard_GRS', 'Standard_GZRS']:
             violations.append({"resourceId": resource_id, "ruleId": "CIS-10.3.12", "description": "Storage Account: Redundancy on critical accounts should be 'geo-redundant storage (GRS)'."})

        # --- 10.2 Azure Blob Storage Checks ---
        delete_retention_policy = blob_svc.get('deleteRetentionPolicy') or {}
        if not delete_retention_policy.get('enabled', False):
            violations.append({"resourceId": resource_id, "ruleId": "CIS-10.2.1", "description": "Blob Storage: Soft delete for blobs should be enabled."})
        
        if not blob_svc.get('isVersioningEnabled', False):
            violations.append({"resourceId": resource_id, "ruleId": "CIS-10.2.2", "description": "Blob Storage: 'Versioning' should be 'Enabled'."})
        
        container_delete_policy = blob_svc.get('containerDeleteRetentionPolicy') or {}
        if not container_delete_policy.get('enabled', False):
            violations.append({"resourceId": resource_id, "ruleId": "CIS-10.3.6-Container", "description": "Blob Storage: Soft delete for containers should be enabled."})

        # --- 10.1 Azure Files Checks ---
        share_delete_policy = file_svc.get('shareDeleteRetentionPolicy') or {}
        if not share_delete_policy.get('enabled', False):
            violations.append({"resourceId": resource_id, "ruleId": "CIS-10.1.1", "description": "Azure Files: Soft delete for Azure File Shares should be enabled."})
        
        protocol_settings = file_svc.get('protocolSettings') or {}
        smb_settings = protocol_settings.get('smb') or {}
        if "SMB3.1.1" not in (smb_settings.get('versions') or ''):
            violations.append({"resourceId": resource_id, "ruleId": "CIS-10.1.2", "description": "Azure Files: 'SMB protocol version' should be 'SMB 3.1.1' or higher."})
        
        if "AES-256-GCM" not in (smb_settings.get('channelEncryption') or ''):
            violations.append({"resourceId": resource_id, "ruleId": "CIS-10.1.3", "description": "Azure Files: 'SMB channel encryption' should be 'AES-256-GCM' or higher."})

    return violations

def main():
    all_violations = analyze_storage_accounts()

    with open('drift_report.json', 'w') as f:
        json.dump(all_violations, f, indent=2)

    print(f"Manual storage analysis complete. Found {len(all_violations)} total violations.")

if __name__ == "__main__":
    main()
