#!/usr/bin/env python3
"""
validate_pci.py

Validate Azure resources against PCI DSS v4.0 controls:
- Storage
- Virtual Machines (VM)
- Identity & Access Management (IAM)
- Databases
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


def get_field(d: Dict[str, Any], keys: List[str]) -> Optional[Any]:
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
        return val.strip().lower() in ("true", "enabled", "yes", "1")
    return bool(val)


def add_violation(violations: List[str], msg: str):
    violations.append(msg)


# -------------------
# Storage checks
# -------------------
def check_storage(resource: Dict[str, Any], violations: List[str]):
    name = resource.get("name", "UnknownStorage")

    # Req 1: Restrict network access
    if get_field(resource, ["networkAcls"]) is None:
        add_violation(violations, f"PCI DSS Req 1 Violation: Storage {name} has no firewall/NSG restrictions.")

    # Req 3: Encryption at rest
    if not truthy(get_field(resource, ["encryptionAtRest"])):
        add_violation(violations, f"PCI DSS Req 3 Violation: Storage {name} not encrypted at rest.")

    # Req 7: Access control
    if not truthy(get_field(resource, ["rbacEnabled"])):
        add_violation(violations, f"PCI DSS Req 7 Violation: Storage {name} does not enforce RBAC.")

    # Req 10: Logging
    if not truthy(get_field(resource, ["loggingEnabled"])):
        add_violation(violations, f"PCI DSS Req 10 Violation: Storage {name} logging not enabled.")


# -------------------
# VM checks
# -------------------
def check_vm(resource: Dict[str, Any], violations: List[str]):
    name = resource.get("name", "UnknownVM")

    # Req 6: Patch/vulnerability
    if not truthy(get_field(resource, ["autoPatchEnabled"])):
        add_violation(violations, f"PCI DSS Req 6 Violation: VM {name} auto-patching disabled.")

    # Req 1 & 7: Restrict inbound traffic
    if not get_field(resource, ["networkSecurityGroup"]):
        add_violation(violations, f"PCI DSS Req 1/7 Violation: VM {name} has no NSG applied.")

    # Req 3: Disk encryption
    if not truthy(get_field(resource, ["diskEncryptionEnabled"])):
        add_violation(violations, f"PCI DSS Req 3 Violation: VM {name} disks not encrypted.")

    # Req 10: Logging
    if not truthy(get_field(resource, ["bootDiagnostics"])):
        add_violation(violations, f"PCI DSS Req 10 Violation: VM {name} diagnostics/logging not enabled.")


# -------------------
# IAM checks
# -------------------
def check_iam(resource: Dict[str, Any], violations: List[str]):
    user = resource.get("userPrincipalName", resource.get("name", "UnknownUser"))

    # Req 7: Role-based access
    if not get_field(resource, ["roleAssignments"]):
        add_violation(violations, f"PCI DSS Req 7 Violation: User {user} has no RBAC roles assigned.")

    # Req 8: MFA
    if not truthy(get_field(resource, ["mfaEnabled"])):
        add_violation(violations, f"PCI DSS Req 8 Violation: User {user} does not have MFA enabled.")

    # Req 7/8: Access review
    if truthy(get_field(resource, ["isDeprecated"])):
        add_violation(violations, f"PCI DSS Req 7/8 Violation: User {user} is deprecated but still active.")

    # Req 8: Password policy
    if not truthy(get_field(resource, ["passwordPolicyCompliant"])):
        add_violation(violations, f"PCI DSS Req 8 Violation: User {user} password policy not compliant.")


# -------------------
# Database checks
# -------------------
def check_db(resource: Dict[str, Any], violations: List[str]):
    name = resource.get("name", "UnknownDB")

    # Req 3 & 4: Encryption at rest and transit
    if not truthy(get_field(resource, ["encryptionAtRest"])):
        add_violation(violations, f"PCI DSS Req 3 Violation: DB {name} not encrypted at rest.")
    if not truthy(get_field(resource, ["sslEnforced"])):
        add_violation(violations, f"PCI DSS Req 4 Violation: DB {name} does not enforce SSL for data in transit.")

    # Req 7: Access control
    if not get_field(resource, ["authorizedUsers"]):
        add_violation(violations, f"PCI DSS Req 7 Violation: DB {name} has no access control defined.")

    # Req 10: Logging/monitoring
    if not truthy(get_field(resource, ["auditingEnabled"])):
        add_violation(violations, f"PCI DSS Req 10 Violation: DB {name} auditing not enabled.")


# -------------------
# Main
# -------------------
def main():
    data = load_data(INPUT_FILE)

    violations: List[str] = []

    for res in data.get("storage", []):
        check_storage(res, violations)
    for res in data.get("vms", []):
        check_vm(res, violations)
    for res in data.get("iam", []):
        check_iam(res, violations)
    for res in data.get("databases", []):
        check_db(res, violations)

    for v in violations:
        print(v)


if __name__ == "__main__":
    main()
