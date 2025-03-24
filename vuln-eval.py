import pandas as pd
import requests
import time
import sys
import os
from datetime import date

# Step 1: Get input filename
if len(sys.argv) < 2:
    print("Usage: python vuln-eval.py <input_csv_file>")
    sys.exit(1)

input_file = sys.argv[1]
if not os.path.isfile(input_file):
    print(f"File not found: {input_file}")
    sys.exit(1)

# Step 2: Set filenames with date
base_name = os.path.splitext(input_file)[0]
today = date.today().isoformat()
output_file = f"{base_name}_enriched_{today}.csv"
kev_file = f"kev_catalog_{today}.json"

# Step 3: Load input CSV
df = pd.read_csv(input_file)

# Step 4: Fetch EPSS scores
def fetch_epss_score(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if data.get("data"):
                return float(data["data"][0]["epss"])
    except Exception as e:
        print(f"Error fetching EPSS for {cve_id}: {e}")
    return 0.0

print("Fetching EPSS scores...")
unique_cves = df["CVE ID"].unique()
epss_scores = {}

for index, cve in enumerate(unique_cves, start=1):
    print(f"  [{index}/{len(unique_cves)}] Fetching EPSS for {cve}...", end="")
    score = fetch_epss_score(cve)
    epss_scores[cve] = score
    print(f" Score: {score}")
    time.sleep(1)

df["EPSS Score"] = df["CVE ID"].map(epss_scores)

# Step 5: Download KEV catalog
kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
print("\nDownloading CISA KEV catalog...")
try:
    response = requests.get(kev_url)
    if response.status_code == 200:
        with open(kev_file, "w") as f:
            f.write(response.text)
        kev_data = response.json().get("vulnerabilities", [])
        print(f"  Downloaded KEV catalog: {len(kev_data)} entries")
    else:
        kev_data = []
        print(f"  Warning: Failed to download KEV catalog (status code: {response.status_code})")
except Exception as e:
    print(f"  Error fetching KEV data: {e}")
    kev_data = []

# Step 6: Build KEV lookup
kev_lookup = {}
for entry in kev_data:
    cve_id = entry.get("cveID")
    if cve_id:
        kev_lookup[cve_id.upper()] = {
            "Title": entry.get("vulnerabilityName", "Not Found in KEV catalog"),
            "Summary": entry.get("shortDescription", ""),
            "KnownExploited": True
        }

# Step 7: NVD CVE lookup
def fetch_nvd_remediation(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            items = data.get("result", {}).get("CVE_Items", [])
            if items:
                desc = items[0]["cve"]["description"]["description_data"][0]["value"]
                refs = items[0]["cve"]["references"]["reference_data"]
                for ref in refs:
                    tags = ref.get("tags", [])
                    if any(t in tags for t in ["Patch", "Vendor Advisory", "Third Party Advisory"]):
                        return f"{desc} - Recommended: {ref.get('url', '')}"
                return desc
    except Exception as e:
        print(f"Error fetching NVD data for {cve_id}: {e}")
    return None

# Step 8: Risk Score Calculation
df["Risk Score"] = (
    df["CVSS Score"] * 0.5 +
    df["EPSS Score"] * 100 * 0.3 +
    df["Asset Criticality"] * 2
)

# Step 9: Enrich Data
titles = []
summaries = []
kev_flags = []
remediations = []

def fallback_remediation(cvss, epss, known_exploited):
    if known_exploited:
        return "Patch immediately. Known to be actively exploited."
    if epss >= 0.5 and cvss >= 7.0:
        return "High likelihood of exploitation. Patch as soon as possible."
    if cvss >= 9.0:
        return "Critical vulnerability. Patch during emergency window."
    elif cvss >= 7.0:
        return "High severity. Patch in next maintenance window."
    elif cvss >= 4.0:
        return "Moderate severity. Include in regular patch cycle."
    else:
        return "Low severity. Defer based on business risk."

print("\nFetching remediation and enrichment...")
for idx, row in df.iterrows():
    cve = row["CVE ID"].upper()
    kev = kev_lookup.get(cve)
    if kev:
        title = kev.get("Title", "Not Found in KEV catalog")
        summary = kev.get("Summary", "")
        known = kev.get("KnownExploited", False)
    else:
        title = "Not Found in KEV catalog"
        summary = ""
        known = False

    titles.append(title)
    summaries.append(summary)
    kev_flags.append("Yes" if known else "No")

    remediation = fetch_nvd_remediation(cve)
    if remediation:
        remediations.append(remediation)
    else:
        remediations.append(fallback_remediation(row["CVSS Score"], row["EPSS Score"], known))

    time.sleep(6)  # NVD rate limit: 5 requests per 30 seconds

df["KEV Title"] = titles
df["KEV Summary"] = summaries
df["Known Exploited"] = kev_flags
df["Remediation"] = remediations

# Step 10: Save results
df.to_csv(output_file, index=False)
print(f"\nUnified enriched CSV saved to: {output_file}")
print(f"KEV catalog saved to: {kev_file}")

# Step 11: Print Top 10
top10 = df.sort_values(by="Risk Score", ascending=False).head(10).copy()
top10.index = range(1, 11)

print("\nTop 10 vulnerabilities by risk score:")
print(top10[[
    "Host", "CVE ID", "CVSS Score", "EPSS Score", "Asset Criticality", "Risk Score", "Known Exploited"
]])