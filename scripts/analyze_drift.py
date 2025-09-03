import json

def get_name_from_id(resource_id):
    return resource_id.split("/")[-1] if resource_id else "unknown"

def record_check(results, rid, pciReq, desc, passed, evidence=""):
    results.append({
        "resourceName": get_name_from_id(rid),
        "pciReq": pciReq,
        "desc": desc,
        "status": "PASS" if passed else "FAIL",
        "evidence": evidence
    })

results = []
record_check(results, "/subscriptions/123/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/mystorage123",
             "3", "Storage: Encryption at rest enabled", True, "services=True")

with open("drift_report.json", "w") as f:
    json.dump(results, f, indent=2)

print("Done. Check drift_report.json")
