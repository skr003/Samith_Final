#!/usr/bin/env python3
"""
validate_cis.py

Reads output/azure.json and prints ONLY CIS Storage-related violation messages.
Implements CIS Microsoft Azure Foundations Benchmark v4.0.0
Section 10: Storage Services
"""

import json
import os
import sys
from typing import Any, Dict, List, Optional

INPUT_FILE = "output/azure.json"


def load_data(path: str) -> Any:
    if not os.path.exists(path):
        print(f"[!] Input file not found: {path}", file=sys.stderr)
        sys.exit(2)
    with open(path, "r") as f:
        return json.load(f)


def get_field_any(d: Dict[str, Any], keys: List[str]) -> Optional[Any]:
    """Check both top-level and .properties keys."""
    for k in keys:
        if k in d:
            return d[k]
    if "properties" in d and isinstance(d["properties"], dict):
        for k in keys:
            if k in d["properties"]:
                return d["properties"][k]
    return None


def truthy(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ("true", "yes", "enabled", "1")
    return bool(val)


def add_violation(violations: List[str], msg: str):
    violations.append(msg)


def check_storage(sa: Dict[str, Any], violations: List[str]):
    # storage account name
    if "account" in sa and isinstance(sa["account"], dict):
        sa_name = sa["account"].get("name", "Unknown")
    else:
        sa_name = sa.get("name", "Unknown")

    # --- CIS 10.1 Azure Files ---
    if not truthy(get_field_any(sa, ["fileSoftDelete"])):
        add_violation(violations, f"CIS 10.1.1 Violation: Azure File Share {sa_name} does not have soft delete enabled.")
    if str(get_field_any(sa, ["smbProtocolVersion"]) or "") < "3.1.1":
        add_violation(violations, f"CIS 10.1.2 Violation: Azure File Share {sa_name} SMB protocol version is below 3.1.1.")
    if "AES-256-GCM" not in str(get_field_any(sa, ["smbChannelEncryption"]) or ""):
        add_violation(violations, f"CIS 10.1.3 Violation: Azure File Share {sa_name} SMB channel encryption is not AES-256-GCM or higher.")

    # --- CIS 10.2 Azure Blob Storage ---
    if not truthy(get_field_any(sa, ["blobSoftDelete"])):
        add_violation(violations, f"CIS 10.2.1 Violation: Blob storage {sa_name} does not have soft delete enabled.")
    if not truthy(get_field_any(sa, ["isVersioningEnabled"])):
        add_violation(violations, f"CIS 10.2.2 Violation: Blob storage {sa_name} does not have versioning enabled.")

    # --- CIS 10.3 Storage Accounts ---
    if not truthy(get_field_any(sa, ["keyRotationReminders"])):
        add_violation(violations, f"CIS 10.3.1.1 Violation: Storage account {sa_name} does not have key rotation reminders enabled.")
    if get_field_any(sa, ["keyCreationTime"]) is None:
        add_violation(violations, f"CIS 10.3.1.2 Violation: Storage account {sa_name} has no record of key regeneration.")
    if truthy(get_field_any(sa, ["allowSharedKeyAccess"])):
        add_violation(violations, f"CIS 10.3.1.3 Violation: Storage account {sa_name} allows shared key access.")
    if not truthy(get_field_any(sa, ["privateEndpoints"])):
        add_violation(violations, f"CIS 10.3.2.1 Violation: Storage account {sa_name} does not use private endpoints.")
    if str(get_field_any(sa, ["publicNetworkAccess"]) or "").lower() != "disabled":
        add_violation(violations, f"CIS 10.3.2.2 Violation: Storage account {sa_name} allows public network access.")
    if str(get_field_any(sa, ["defaultAction"]) or "").lower() != "deny":
        add_violation(violations, f"CIS 10.3.2.3 Violation: Storage account {sa_name} does not default deny network access.")
    if not truthy(get_field_any(sa, ["defaultToAzureADAuth"])):
        add_violation(violations, f"CIS 10.3.3.1 Violation: Storage account {sa_name} is not defaulting to Microsoft Entra authorization.")
    if not truthy(get_field_any(sa, ["enableHttpsTrafficOnly"])):
        add_violation(violations, f"CIS 10.3.4 Violation: Storage account {sa_name} does not enforce secure transfer.")
    if "AzureServices" not in str(get_field_any(sa, ["bypass"]) or ""):
        add_violation(violations, f"CIS 10.3.5 Violation: Storage account {sa_name} does not allow trusted Azure services.")
    if not truthy(get_field_any(sa, ["containerDeleteRetentionPolicy"])):
        add_violation(violations, f"CIS 10.3.6 Violation: Storage account {sa_name} does not have soft delete enabled for containers/blobs.")
    if str(get_field_any(sa, ["minimumTlsVersion"]) or "") not in ("TLS1_2", "1.2", "TLS1.2"):
        add_violation(violations, f"CIS 10.3.7 Violation: Storage account {sa_name} TLS version is not 1.2.")
    if truthy(get_field_any(sa, ["allowCrossTenantReplication"])):
        add_violation(violations, f"CIS 10.3.8 Violation: Storage account {sa_name} allows cross-tenant replication.")
    if truthy(get_field_any(sa, ["allowBlobPublicAccess"])):
        add_violation(violations, f"CIS 10.3.9 Violation: Storage account {sa_name} allows anonymous blob access.")
    locks = get_field_any(sa, ["resourceLocks"]) or []
    if "Delete" not in str(locks):
        add_violation(violations, f"CIS 10.3.10 Violation: Storage account {sa_name} has no delete lock.")
    if "ReadOnly" not in str(locks):
        add_violation(violations, f"CIS 10.3.11 Violation: Storage account {sa_name} has no read-only lock.")
    redundancy = str(get_field_any(sa, ["sku"]) or "")
    if "GRS" not in redundancy:
        add_violation(violations, f"CIS 10.3.12 Violation: Storage account {sa_name} is not geo-redundant (GRS).")


def resource_is_storage(r: Dict[str, Any]) -> bool:
    t = (r.get("type") or "").lower()
    return "storage" in t or "storageaccounts" in t or "microsoft.storage" in t


def main():
    data = load_data(INPUT_FILE)

    # normalize resource list
    if isinstance(data, dict) and "resource_changes" in data:
        resources = data["resource_changes"]
    elif isinstance(data, list):
        resources = data
    else:
        resources = []

    violations: List[str] = []

    for sa in resources:
        if not isinstance(sa, dict):
            continue
        if resource_is_storage(sa):
            check_storage(sa, violations)

    for v in violations:
        print(v)


if __name__ == "__main__":
    main()
