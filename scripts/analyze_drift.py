# scripts/analyze_drift.py
import json

def get_name_from_id(rid: str) -> str:
    """Extract resource name from resourceId (last segment)."""
    if not rid:
        return ""
    return rid.split("/")[-1]

def get_group_from_id(rid: str) -> str:
    """Extract resource group from resourceId (after 'resourceGroups/')."""
    if not rid or "resourceGroups/" not in rid:
        return ""
    return rid.split("resourceGroups/")[1].split("/")[0]

# Map PCI DSS requirement to control description
PCI_CONTROLS = {
    "1": "Install and maintain network security controls (firewalls).",
    "3": "Protect stored cardholder data (encryption at rest).",
    "3,4": "Protect stored and transmitted cardholder data (encryption).",
    "6": "Develop and maintain secure systems and applications (patching).",
    "7": "Restrict access to cardholder data by business need to know.",
    "8": "Identify and authenticate access to system components (MFA).",
    "10": "Log and monitor all access to system components."
}

def record_check(results, rid, pciReq, rgroup, rtype, desc, passed):
    results.append({
        "Control": f"Req. {pciReq}",
        "Control/Rule": PCI_CONTROLS.get(pciReq, desc),
        "Resource Group": rgroup,
        "Resource": rtype,
        "Resource Name": get_name_from_id(rid),
        "Audit Status": "Passed" if passed else "Failed"
    })

def analyze_storage(data, results):
    acc = data.get("account", {})
    rid = acc.get("id")
    if not rid: return
    rgroup = get_group_from_id(rid)

    passed = acc.get("publicNetworkAccess") == "Disabled"
    record_check(results, rid, "1", rgroup, "Storage Account", "Public network access disabled", passed)

    passed = bool(acc.get("encryption", {}).get("services"))
    record_check(results, rid, "3", rgroup, "Storage Account", "Encryption at rest enabled", passed)

    passed = not acc.get("allowBlobPublicAccess", True)
    record_check(results, rid, "7", rgroup, "Storage Account", "Blob anonymous access disabled", passed)

    passed = bool(acc.get("diagnosticSettings"))
    record_check(results, rid, "10", rgroup, "Storage Account", "Diagnostics enabled", passed)

def analyze_vms(data, results):
    for vm in data.get("vms", []):
        rid = vm.get("id")
        rgroup = get_group_from_id(rid)

        passed = vm.get("latestModelApplied", False)
        record_check(results, rid, "6", rgroup, "Virtual Machine", "Latest OS model/patch applied", passed)

        passed = bool(vm.get("networkProfile"))
        record_check(results, rid, "1", rgroup, "Virtual Machine", "NSG restrictions applied", passed)

        passed = bool(vm.get("storageProfile", {}).get("osDisk", {}).get("encryptionSettings"))
        record_check(results, rid, "3", rgroup, "Virtual Machine", "OS disk encryption enabled", passed)

        passed = bool(vm.get("diagnosticsProfile"))
        record_check(results, rid, "10", rgroup, "Virtual Machine", "Diagnostics logging enabled", passed)

def analyze_iam(data, results):
    for user in data.get("users", []):
        uid = user.get("id")

        passed = user.get("userType") != "Guest"
        record_check(results, uid, "7", "IAM", "User Account", "No guest users in privileged roles", passed)

        passed = user.get("mfaEnabled", False)
        record_check(results, uid, "8", "IAM", "User Account", "MFA enforced", passed)

def analyze_db(data, results):
    for db in data.get("databases", []):
        rid = db.get("id")
        rgroup = get_group_from_id(rid)

        passed = bool(db.get("encryptionProtector"))
        record_check(results, rid, "3,4", rgroup, "SQL Database", "Transparent Data Encryption enabled", passed)

        passed = bool(db.get("containmentState"))
        record_check(results, rid, "7", rgroup, "SQL Database", "Proper access containment", passed)

        passed = bool(db.get("auditSettings"))
        record_check(results, rid, "10", rgroup, "SQL Database", "Auditing/logging enabled", passed)

def main():
    try:
        with open("output/azure.json", "r") as f:
            resources = json.load(f)
    except FileNotFoundError:
        print("No PCI DSS data file found (azure.json). Did you run the collector script
