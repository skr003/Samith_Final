import json
import os

INPUT_FILE = "azure.json"
OUTPUT_FILE = "drift_report.json"

def get_name_from_id(resource_id):
    """Extract resource name (after last /) from resourceId"""
    return resource_id.split("/")[-1] if resource_id else "unknown"

def record_check(results, rid, pciReq, desc, passed, evidence=""):
    results.append({
        "resourceName": get_name_from_id(rid),
        "pciReq": pciReq,
        "desc": desc,
        "status": "PASS" if passed else "FAIL",
        "evidence": evidence
    })

def analyze():
    if not os.path.exists(INPUT_FILE):
        print(f"No PCI DSS data file found ({INPUT_FILE}). Did you run the collector script?")
        return

    with open(INPUT_FILE, "r") as f:
        data = json.load(f)

    results = []

    # Iterate through resources
    for res in data.get("resources", []):
        rid = res.get("id", "unknown")

        # Storage account checks
        if "Microsoft.Storage/storageAccounts" in res.get("type", ""):
            acc = res.get("values", {})

            # PCI DSS Req 1 & 7: Restrict network access
            val = acc.get("publicNetworkAccess")
            passed = val == "Disabled"
            record_check(results, rid, "1,7", "Storage: Public network access disabled", passed, f"publicNetworkAccess={val}")

            # PCI DSS Req 3: Encryption at rest enabled
            val = acc.get("encryption", {}).get("services")
            passed = bool(val)
            record_check(results, rid, "3", "Storage: Encryption at rest enabled", passed, f"services={val}")

            # PCI DSS Req 10: Logging enabled
            diag = acc.get("diagnostics_profile", {}).get("boot_diagnostics", {}).get("enabled")
            passed = diag is True
            record_check(results, rid, "10", "Storage: Boot diagnostics enabled", passed, f"boot_diagnostics={diag}")

        # VM checks
        if "Microsoft.Compute/virtualMachines" in res.get("type", ""):
            vm = res.get("values", {})

            # PCI DSS Req 2: Enforce secure SSH key
            key = vm.get("admin_ssh_key", [{}])[0].get("public_key", "").strip()
            passed = bool(key)
            record_check(results, rid, "2", "VM: Secure SSH key configured", passed, f"ssh_key_present={bool(key)}")

            # PCI DSS Req 10: Diagnostic logging
            diag = vm.get("diagnostics_profile", {}).get("boot_diagnostics", {}).get("enabled")
            passed = diag is True
            record_check(results, rid, "10", "VM: Boot diagnostics enabled", passed, f"boot_diagnostics={diag}")

        # IAM checks
        if "Microsoft.Authorization/roleAssignments" in res.get("type", ""):
            iam = res.get("values", {})

            # PCI DSS Req 7: Least privilege
            role = iam.get("roleDefinitionName")
            passed = role not in ["Owner", "Contributor"]
            record_check(results, rid, "7", "IAM: Least privilege enforced", passed, f"role={role}")

            # PCI DSS Req 8: MFA required
            mfa = iam.get("mfaEnabled")
            passed = mfa is True
            record_check(results, rid, "8", "IAM: MFA enabled", passed, f"mfaEnabled={mfa}")

        # Database checks
        if "Microsoft.DBfor" in res.get("type", ""):
            db = res.get("values", {})

            # PCI DSS Req 3: Encryption enabled
            enc = db.get("sslEnforcement")
            passed = enc == "Enabled"
            record_check(results, rid, "3", "DB: SSL enforcement enabled", passed, f"sslEnforcement={enc}")

            # PCI DSS Req 7: Public network disabled
            pub = db.get("publicNetworkAccess")
            passed = pub == "Disabled"
            record_check(results, rid, "7", "DB: Public network access disabled", passed, f"publicNetworkAccess={pub}")

    # Save results to JSON
    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, indent=2)

    print(f"Drift analysis complete. Results written to {OUTPUT_FILE}")

if __name__ == "__main__":
    analyze()
