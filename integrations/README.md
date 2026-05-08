# Integrations: Client Glue Scripts

This directory contains lightweight integration scripts (Bash/Python) that bridge third-party SaaS security tools with the Jula Evidence Collector's BYOE (Bring Your Own Evidence) ingestion pipeline.

## Purpose

Each script pulls data from an external scanning or monitoring platform (e.g., Aikido, Snyk, Qualys, Nessus) and transforms the API response into the standardized Jula BYOE JSON schema defined in [`configs/schemas/`](../configs/schemas/). The resulting JSON file is dropped into the `evidence-output/` directory where the Jula FileDrop provider picks it up for cryptographic hashing, schema validation, and SOC 2 criteria mapping.

## How to Run

These scripts are intended to be executed by the client, entirely separate from the core Jula Go engine. Common execution patterns include:

- **GitHub Actions:** Schedule a workflow that runs the script on a cron, then uploads the output to your evidence GCS/S3 bucket.
- **Local Cron Job:** Add an entry to your `crontab` for periodic evidence generation.
- **Manual Execution:** Run the script ad-hoc before an audit cycle to refresh evidence.

## Script Index

| Script | Source Tool | Output Schema | Description |
| :--- | :--- | :--- | :--- |
| [fetch_aikido.sh](fetch_aikido.sh) | [Aikido Security](https://www.aikido.dev) | `byoe_vulnerability_scan.json` | Exports open issues from Aikido, counts severities, and generates a BYOE vulnerability scan evidence file. |

## Adding a New Integration

1. Create a new script in this directory (e.g., `fetch_snyk.sh`).
2. Query the tool's API and transform the response into the BYOE schema from `configs/schemas/`.
3. Save the output to `evidence-output/`.
4. Update the Script Index table above.
