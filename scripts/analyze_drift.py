# scripts/analyze_pci_dss.py
import json


def analyze_pci_dss():
    """
    Manually checks Azure resources against PCI DSS v4.0 controls:
    - Storage
    - Virtual Machines (VMs)
    - Identity & Access Management (IAM)
    - Databases
    """

    try:
        with open("output/azure.json", "r") as f:
            all_resources = json.load(f)
    except FileNotFoundError:
        return []

    violations = []

    for res in all_resources:
        rtype = res.get("type")

        # -------------------
        # Storage checks
        # -------------------
        if rtype == "storage":
            acc = res.get("account", {})
            file_svc = res.get("fileService", {})

            rid = acc.get("id", res.get("name", "UnknownStorage"))

            # Req 1: Restrict network access
            if acc.get("networkAcls") is None:
                violations.append({
                    "resourceId": rid,
                    "ruleId": "PCI-1-Storage",
                    "description": "Storage: No NSG/firewall restrictions."
                })

            # Req 3: Encryption at rest
            if not acc.get("encryption", {}).get("services"):
                violations.append({
                    "resourceId": rid,
                    "ruleId": "PCI-3-Storage",
                    "description": "Storage: Encryption at rest not enforced."
                })

            # Req 7: Access control
            if not acc.get("identity"):
                violations.append({
                    "resourceId": rid,
                    "ruleId": "PCI-7-Storage",
                    "description": "Storage: RBAC not enabled."
                })

            # Req 10: Logging
            if not file_svc.get("logging", {}):
                violations.append({
                    "resourceId": rid,
                    "ruleId": "PCI-10-Storage",
                    "description": "Storage: Logging not enabled."
                })

        # -------------------
        # VM checks
        # -------------------
        elif rtype == "vm":
            vm = res.get("vm", {})
            diag = res.get("diagnostics", {})

            rid = vm.get("id", vm.get("name", "UnknownVM"))

            # Req 6: Patch/vulnerability
            if not vm.get("osProfile", {}).get("windowsConfiguration", {}).get("patchSettings", {}):
                violations.append({
                    "resourceId": rid,
                    "ruleId": "PCI-6-VM",
                    "description": "VM: Auto patching not enabled."
                })

            # Req 1 & 7: Restrict inbound traffic
            if not vm.get("networkProfile", {}).get("networkInterfaces"):
                violations.append({
                    "resourceId": rid,
                    "ruleId": "PCI-1-VM",
                    "description": "VM: No NSG/network interface restrictions."
                })

            # Req 3: Disk encryption
            if not vm.get("storageProfile", {}).get("osDisk", {}).get("encryptionSettings"):
                violations.append({
                    "resourceId": rid,
                    "ruleId": "PCI-3-VM",
                    "description": "VM: Disks not encrypted."
                })

            # Req 10: Logging
            if not diag.get("bootDiagnostics"):
                violations.append({
                    "resourceId": rid,
                    "ruleId": "PCI-10-VM",
                    "description": "VM: Diagnostics/logging not enabled."
                })

        # -------------------
        # IAM checks
        # -------------------
        elif rtype == "iam":
            user = res.get("user", {})
            upn = user.get("userPrincipalName", user.get("name", "UnknownUser"))

            # Req 7: Role-based access
            if not res.get("roleAssignments"):
                violations.append({
                    "resourceId": upn,
                    "ruleId": "PCI-7-IAM",
                    "description": f"IAM: User {upn} has no RBAC roles."
                })

            # Req 8: MFA
            if not user.get("mfaEnabled", False):
                violations.append({
                    "resourceId": upn,
                    "ruleId": "PCI-8-IAM",
                    "description": f"IAM: User {upn} does not have MFA enabled."
                })

            # Req 7/8: Access review
            if user.get("isDeprecated", False):
                violations.append({
                    "resourceId": upn,
                    "ruleId": "PCI-7-8-IAM",
                    "description": f"IAM: Deprecated user {upn} still active."
                })

            # Req 8: Password policy
            if not user.get("passwordPolicyCompliant", False):
                violations.append({
                    "resourceId": upn,
                    "ruleId": "PCI-8-IAM",
                    "description": f"IAM: User {upn} password policy not compliant."
                })

        # -------------------
        # Database checks
        # -------------------
        elif rtype == "database":
            db = res.get("db", {})
            rid = db.get("id", db.get("name", "UnknownDB"))

            # Req 3 & 4: Encryption
            if not db.get("encryption", {}).get("enabled", False):
                violations.append({
                    "resourceId": rid,
                    "ruleId": "PCI-3-DB",
                    "description": "DB: Encryption at rest not enabled."
                })
            if not db.get("sslEnforced", False):
                violations.append({
                    "resourceId": rid,
                    "ruleId": "PCI-4-DB",
                    "description": "DB: SSL/TLS not enforced for transit."
                })

            # Req 7: Access controls
            if not db.get("authorizedUsers"):
                violations.append({
                    "resourceId": rid,
                    "ruleId": "PCI-7-DB",
                    "description": "DB: No access control defined."
                })

            # Req 10: Activity monitoring
            if not res.get("auditing", {}).get("state") == "Enabled":
                violations.append({
                    "resourceId": rid,
                    "ruleId": "PCI-10-DB",
                    "description": "DB: Auditing not enabled."
                })

    return violations


def main():
    violations = analyze_pci_dss()

    if not violations:
        print("[DEBUG] No violations found. Dumping parsed resources for inspection...")
        with open("output/azure.json", "r") as f:
            data = json.load(f)
            print(json.dumps(data[:3], indent=2))  # show first 3 entries

    with open("pci_dss_report.json", "w") as f:
        json.dump(violations, f, indent=2)

    print(f"PCI DSS analysis complete. Found {len(violations)} total violations.")



if __name__ == "__main__":
    main()
