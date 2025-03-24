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
