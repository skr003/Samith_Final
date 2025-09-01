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

    # Save final JSON in table-like format
    with open("drift_report.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"PCI DSS analysis complete. Report saved to drift_report.json with {len(results)} checks.")

if __name__ == "__main__":
    main()
