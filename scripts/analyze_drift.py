# scripts/analyze_drift.py
import json

def record_check(results, rid, pciReq, desc, passed):
    results.append({
        "resourceId": rid,
        "pciReq": pciReq,
        "desc": desc,
        "status": "PASS" if passed else "FAIL"
    })

def analyze_storage(data, results):
    acc = data.get("account", {})
    rid = acc.get("id")
    if not rid: return

    # PCI DSS Req 1 & 7: Restrict network access
    passed = acc.get("publicNetworkAccess") == "Disabled"
    record_check(results, rid, "1,7", "Storage: Public network access disabled", passed)

    # PCI DSS Req 3: Encrypt data at rest
    passed = bool(acc.get("encryption", {}).get("services"))
    record_check(results, rid, "3", "Storage: Encryption at rest enabled", passed)

    # PCI DSS Req 7: Blob anonymous access
    passed = not acc.get("allowBlobPublicAccess", True)
    record_check(results, rid, "7", "Storage: Blob anonymous access disabled", passed)

    # PCI DSS Req 10: Logging
    passed = bool(acc.get("diagnosticSettings"))
    record_check(results, rid, "10", "Storage: Diagnostics enabled", passed)

def analyze_vms(data, results):
    for vm in data.get("vms", []):
        rid = vm.get("id")

        passed = vm.get("latestModelApplied", False)
        record_check(results, rid, "6", "VM: Latest OS model/patch applied", passed)

        passed = bool(vm.get("networkProfile"))
        record_check(results, rid, "1,7", "VM: NSG restrictions applied", passed)

        passed = bool(vm.get("storageProfile", {}).get("osDisk", {}).get("encryptionSettings"))
        record_check(results, rid, "3", "VM: OS disk encryption enabled", passed)

        passed = bool(vm.get("diagnosticsProfile"))
        record_check(results, rid, "10", "VM: Diagnostics logging enabled", passed)

def analyze_iam(data, results):
    for user in data.get("users", []):
        uid = user.get("id")

        passed = user.get("userType") != "Guest"
        record_check(results, uid, "7", "IAM: No guest users in privileged roles", passed)

        passed = user.get("mfaEnabled", False)
        record_check(results, uid, "8", "IAM: MFA enforced", passed)

def analyze_db(data, results):
    for db in data.get("databases", []):
        rid = db.get("id")

        passed = bool(db.get("encryptionProtector"))
        record_check(results, rid, "3,4", "DB: Transparent Data Encryption enabled", passed)

        passed = bool(db.get("containmentState"))
        record_check(results, rid, "7", "DB: Proper access containment", passed)

        passed = bool(db.get("auditSettings"))
        record_check(results, rid, "10", "DB: Auditing/logging enabled", passed)

def main():
    try:
        with open("output/azure.json", "r") as f:
            resources = json.load(f)
    except FileNotFoundError:
        print("No PCI DSS data file found (azure.json). Did you run the collector script?")
        return

    results = []

    for item in resources:
        if "account" in item and "blobService" in item:
            analyze_storage(item, results)
            continue

        itype = item.get("type")
        if itype == "storage":
            analyze_storage(item, results)
        elif itype == "vm":
            analyze_vms(item, results)
        elif itype == "iam":
            analyze_iam(item, results)
        elif itype == "db":
            analyze_db(item, results)

    # Save JSON with both PASS and FAIL results
    with open("drift_report.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"PCI DSS analysis complete. Report saved to drift_report.json with {len(results)} total checks.")

if __name__ == "__main__":
    main()
