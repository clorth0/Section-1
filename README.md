# Vulnerability Enrichment and Risk Prioritization Script

This Python script enriches and prioritizes vulnerabilities from scan data using a combination of real-time threat intelligence sources. It is designed to support technical assessment workflows and security automation efforts.

## Features

- Accepts CSV input with vulnerability scan data (CVE ID, CVSS Score, Asset Criticality)
- Fetches EPSS (Exploit Prediction Scoring System) scores via FIRST.org API
- Enriches with metadata from CISA's Known Exploited Vulnerabilities (KEV) catalog:
  - Vulnerability title
  - Summary
  - Known exploited flag
- Queries NVD (National Vulnerability Database) API for:
  - CVE description
  - References (patch and advisory URLs)
- Generates remediation guidance using a hybrid approach:
  - Uses NVD recommendations when available
  - Falls back to severity-based logic when necessary
- Calculates a composite risk score based on CVSS, EPSS, and asset criticality
- Outputs enriched vulnerability data to a single CSV
- Prints a summary of the top 10 highest-risk vulnerabilities to the console

## Inputs

- A CSV file with the following columns:
  - `CVE ID`
  - `CVSS Score`
  - `Asset Criticality`
  - `Host` (optional but included in sample datasets)

## Output

- `<input_basename>_enriched_<YYYY-MM-DD>.csv`: Contains all enriched data fields
- `kev_catalog_<YYYY-MM-DD>.json`: Cached copy of the CISA KEV catalog
- Terminal output: Prints the top 10 vulnerabilities by calculated risk score

## Example Usage

```bash
python3 vuln-eval.py TVM_-_Section_-_1.csv

## Dependencies

* Python 3.7+
* pandas
* requests

### Install Required Packages
pip install pandas requests

## Error Handling

* File and input validation: Confirms that input CSV exists and has required structure.
* EPSS API requests: Errors are caught and logged per-CVE, and a default score of 0.0 is applied if a request fails.
* CISA KEV catalog download: If the feed cannot be fetched, enrichment continues with defaults, and a warning is printed.
* NVD API lookup: If the NVD API fails or a CVE is not found, the script gracefully falls back to severity-based remediation recommendations.
* Rate limiting: Complies with NVD’s public API rate limits (maximum 5 requests per 30 seconds) using time.sleep.

## Notes
* If a CVE is not found in the KEV catalog, the title will be marked as "Not Found in KEV catalog".
* The script does not require API keys, but support can be added easily.
* For large datasets, NVD API rate limiting may increase runtime. A key-based approach is recommended for scale.
