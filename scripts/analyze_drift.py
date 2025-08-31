# scripts/analyze_drift.py
import json

def analyze_storage(data, violations):
    acc = data.get("account", {})
    rid = acc.get("id")
    if not rid: return

    # PCI DSS Req 1 & 7: Restrict network access
    if acc.get("publicNetworkAccess") != "Disabled":
        violations.append({"resourceId": rid, "pciReq": "1,7", "desc": "Storage: Public network access should be disabled."})

    # PCI DSS Req 3: Encrypt data at rest
    if not acc.get("encryption", {}).get("services"):
        violations.append({"resourceId": rid, "pciReq": "3", "desc": "Storage: Encryption at rest must be enabled."})

    # PCI DSS Req 7: Access control
    if acc.get("allowBlobPublicAccess", True):
        violations.append({"resourceId": rid, "pciReq": "7", "desc": "Storage: Blob anonymous access should be disabled."})

    # PCI DSS Req 10: Logging
    if not acc.get("diagnosticSettings"):
        violations.append({"resourceId": rid, "pciReq": "10", "desc": "Storage: Access logging/diagnostics not enabled."})

def analyze_vms(data, violations):
    for vm in data.get("vms", []):
        rid = vm.get("id")

        # PCI DSS Req 6: Patch & vulnerability management
        if not vm.get("latestModelApplied", False):
            violations.append({"resourceId": rid, "pciReq": "6", "desc": "VM: Not running latest OS model/patch."})

        # PCI DSS Req 1,7: Restrict inbound traffic
        if not vm.get("networkProfile"):
            violations.append({"resourceId": rid, "pciReq": "1,7", "desc": "VM: Missing network profile/NSG restrictions."})

        # PCI DSS Req 3: Encrypt disks
        if not vm.get("storageProfile", {}).get("osDisk", {}).get("encryptionSettings"):
            violations.append({"resourceId": rid, "pciReq": "3", "desc": "VM: OS disk encryption not enabled."})

        # PCI DSS Req 10: Logging
        if not vm.get("diagnosticsProfile"):
            violations.append({"resourceId": rid, "pciReq": "10", "desc": "VM: Diagnostics logging not enabled."})

def analyze_iam(data, violations):
    for user in data.get("users", []):
        uid = user.get("id")

        # PCI DSS Req 7: Least privilege
        if user.get("userType") == "Guest":
            violations.append({"resourceId": uid, "pciReq": "7", "desc": "IAM: Guest users must not have privileged roles."})

        # PCI DSS Req 8: MFA
        if not user.get("mfaEnabled", False):
            violations.append({"resourceId": uid, "pciReq": "8", "desc": "IAM: MFA not enforced for this user."})

def analyze_db(data, violations):
    for db in data.get("databases", []):
        rid = db.get("id")

        # PCI DSS Req 3 & 4: Encryption at rest and in transit
        if not db.get("encryptionProtector"):
            violations.append({"resourceId": rid, "pciReq": "3,4", "desc": "DB: Transparent Data Encryption not enabled."})

        # PCI DSS Req 7: Access control
        if not db.get("containmentState"):
            violations.append({"resourceId": rid, "pciReq": "7", "desc": "DB: Missing proper access containment."})

        # PCI DSS Req 10: Monitoring
        if not db.get("auditSettings"):
            violations.append({"resourceId": rid, "pciReq": "10", "desc": "DB: Auditing/logging not enabled."})

def main():
    try:
        with open("output/azure.json", "r") as f:
            resources = json.load(f)
    except FileNotFoundError:
        print("No PCI DSS data file found (azure.json). Did you run the collector script?")
        return

    violations = []

    for item in resources:
        # Backward-compatible: old CIS storage JSON has no "type"
        if "account" in item and "blobService" in item:
            analyze_storage(item, violations)
            continue

        itype = item.get("type")
        if itype == "storage":
            analyze_storage(item, violations)
        elif itype == "vm":
            analyze_vms(item, violations)
        elif itype == "iam":
            analyze_iam(item, violations)
        elif itype == "db":
            analyze_db(item, violations)

    with open("drift_report.json", "w") as f:
        json.dump(violations, f, indent=2)

    print(f"PCI DSS analysis complete. Found {len(violations)} violations.")


if __name__ == "__main__":
    main()
