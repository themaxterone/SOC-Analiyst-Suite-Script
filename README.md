# SOC Analyst Suite — Fluent Edition (`gui_soc_suite.py`)

A desktop security investigation suite built with Windows 11 Fluent Design (`customtkinter`). It unifies Microsoft Entra ID sign-in audits (single account & bulk), customizable **Entra ID Protection Risky User** detection (`High`, `Medium`, `Low`, `All`), **Intigriti** bug bounty IP verification, **AbuseIPDB** threat intelligence lookups, and concurrent API quota monitoring into a single graphical application.

---

## Table of Contents

1. [Overview & Architecture](#overview--architecture)
2. [Key Features](#key-features)
3. [Prerequisites & Dependencies](#prerequisites--dependencies)
4. [Installation Guide](#installation-guide)
5. [Configuration](#configuration)
6. [Usage & Execution](#usage--execution)
7. [Module Breakdown & Workflows](#module-breakdown--workflows)
   - [Tab 1: User Sign-ins Audit (Single & Bulk)](#tab-1-user-sign-ins-audit-single--bulk)
   - [Tab 2: Risky Users (High / Medium / Low / All)](#tab-2-risky-users-high--medium--low--all)
   - [Tab 3: IP Threat Searcher (Intigriti & AbuseIPDB)](#tab-3-ip-threat-searcher-intigriti--abuseipdb)
   - [Tab 4: API Keys Status](#tab-4-api-keys-status)
8. [Directory Structure & Outputs](#directory-structure--outputs)
9. [Corporate Network, Permissions & SSL Troubleshooting](#corporate-network-permissions--ssl-troubleshooting)

---

## Overview & Architecture

Corporate security baselines (such as Microsoft Defender for Endpoint, WDAC, or AppLocker) often restrict the execution of detached background scripts using `.pyw` or `pythonw.exe`.

`gui_soc_suite.py` runs directly via standard `python.exe` while offloading all network API calls, Microsoft OAuth2 PKCE interactive authentication flows, and bulk threat intelligence lookups into asynchronous background threads (`threading.Thread`), keeping the graphical user interface responsive at all times.

---

## Key Features

- **Windows 11 Fluent GUI**: Built using `customtkinter` with rounded controls, responsive layouts, and an instant **Dark Mode / Light Mode** toggle.
- **Color-Coded Virtual Consoles**: Streams live execution steps highlighting successes (green), errors/threats (red), warnings/rate limits (yellow), info prompts (blue), and section dividers (purple).
- **Single & Bulk Account Sign-in Auditing**: Audit an individual UPN or pass a `.txt` file containing multiple accounts to produce a unified CSV and a clean HTML report featuring a per-account breakdown table (with Conditional Access omitted from the HTML view for streamlined reading).
- **Granular Entra ID Protection Scanner (`Risky Users`)**:
  - Select target risk severity via a segmented control (**High**, **Medium**, **Low**, or **All**).
  - Filter detections by recency using **Risk Updated (Days ago)** (`riskLastUpdatedDateTime`), or set `0` to query all historical active detections.
  - Launch a one-click bulk sign-in audit across all discovered accounts.
- **Prioritized Threat Intelligence Engine (`IP Threat Searcher`)**:
  - **Intigriti Verification (`v2/iplookup`)**: Optionally checks IPs against Intigriti first (`exists=True`). Confirmed authorized researcher traffic skips AbuseIPDB queries (saving API quota) and is automatically omitted from all exported files.
  - **Actionable Threshold Filtering**: When Intigriti filtering is active, low-confidence IPs (`abuseConfidenceScore <= 10%`) are also excluded from exports so only actionable threats (`score > 10%`) are written to the HTML, CSV, and firewall blocklist.
  - **AbuseIPDB Enrichment & Key Rotation**: Evaluates external IPs using in-memory caching (`IP_CACHE`), automatic exclusion of private (RFC 1918) and loopback ranges, and automatic multi-key rotation upon hitting HTTP 429 rate limits.
- **Interactive Dashboards**: Standalone HTML reports featuring summary metric cards, live search, per-account quick filters, and bold filter buttons (**All**, **Success**, **Failures**, **Malicious IP**, **Suspicious IP**, **Clean IP**).

---

## Prerequisites & Dependencies

### Python Environment
- Python 3.8+ (Standard Python or Anaconda/Miniconda)
- Required Python libraries:
  - `customtkinter` (Modern Fluent GUI framework)
  - `msal` (Microsoft Authentication Library for PKCE interactive login)
  - `requests` (HTTP API communication)
  - `urllib3` (SSL/TLS warning management)

### Microsoft Entra ID Requirements
- **Tenant License**: Microsoft Entra ID P2 (required for Identity Protection `riskyUsers` queries) or P1 (for standard `signIns` queries).
- **Delegated Permissions**:
  - `AuditLog.Read.All`
  - `IdentityRiskyUser.Read.All`
- **Client ID**: Uses Microsoft's official pre-authorized **Microsoft Graph Command Line Tools** public client ID (`14d82eec-204b-4c2f-b7e8-296a70dab67e`) to support both scopes without requiring a custom App Registration.
- **Directory Role**: The authenticating analyst must hold at least *Security Reader*, *Security Operator*, *Global Reader*, or *Security Administrator*.

---

## Installation Guide

### Option 1: Using Anaconda Prompt (Recommended)

1. Open **Anaconda Prompt** from the Windows Start menu.
2. Install the required libraries:
   ```bash
   pip install customtkinter msal requests urllib3
   ```

### Option 2: Using Standard Python (Windows CMD / PowerShell / Linux)

1. Open your terminal or PowerShell console.
2. Install dependencies via `pip`:
   ```bash
   pip install customtkinter msal requests urllib3
   ```

---

## Configuration

1. Place `gui_soc_suite.py` in your working directory.
2. Open the file in a text editor (VS Code, Notepad, etc.).
3. Configure your Microsoft `CLIENT_ID`, your **Intigriti Access Token**, and your **AbuseIPDB API Keys** near the top of the script:
   ```python
   # Microsoft Graph Command Line Tools official public Client ID
   CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
   AUTHORITY = "https://login.microsoftonline.com/organizations"

   # Intigriti Access Token (Company / Researcher IP Verification)
   INTIGRITI_ACCESS_TOKEN = "YOUR_INTIGRITI_ACCESS_TOKEN"
   INTIGRITI_API_URL = "https://api.intigriti.com/external/company/v2/iplookup"

   # AbuseIPDB API Keys Pool
   ABUSEIPDB_API_KEYS = [
       "YOUR_ABUSEIPDB_KEY_1",
       "YOUR_ABUSEIPDB_KEY_2",
       "YOUR_ABUSEIPDB_KEY_3"
   ]
   ```
4. Save the file.

---

## Usage & Execution

Because corporate endpoint security policies (AppLocker / WDAC) often block `pythonw.exe` and `.pyw` files, always run the suite using standard `python.exe`:

1. Open **Anaconda Prompt** or **PowerShell**.
2. Navigate to your working folder:
   ```cmd
   cd "C:\Users\<YourUser>\Documents\iplookup"
   ```
3. Launch the graphical interface:
   ```cmd
   python gui_soc_suite.py
   ```

---

## Module Breakdown & Workflows

### Tab 1: User Sign-ins Audit (Single & Bulk)
- **Single Account**: Enter a single corporate email/UPN (e.g., `user@company.com`).
- **Bulk File (.txt)**: Click **Browse** and load a `.txt` file containing multiple email addresses (supports one per line or comma/space-separated formats; emails are automatically extracted and deduplicated).
- **Days to Query**: Set the historical lookback period in days (defaults to `15`).
- **Enrich IPs Checkbox**: Cross-references external source IPs against AbuseIPDB and adds risk levels, confidence scores, and attack categories.
- **Output**: Saves a unified `.csv` and a streamlined `.html` dashboard inside `signInsLogs/`. For bulk audits, the HTML includes an **Account Investigation Breakdown** table with one-click per-user log filtering.

### Tab 2: Risky Users (High / Medium / Low / All)
- **Risk Level Selector**: Choose between **High**, **Medium**, **Low**, or **All** active risk levels (`riskState eq 'atRisk'`).
- **Risk Updated (Days ago)**: Filters accounts whose `riskLastUpdatedDateTime` falls within the specified number of days (defaults to `7`; set `0` to include all active detections regardless of update date).
- **Scan Risky Users**: Authenticates against Microsoft Graph and queries `/identityProtection/riskyUsers` using the selected filters.
- **Audit Detected Sign-ins**: Once risky accounts are detected, click this button (or accept the prompt) to run a full bulk sign-in investigation across all discovered users for the specified **Sign-ins Audit Window (Days)**.
- **Output**: Generates `signins_intel_RISKY_<LEVEL>_<N>accounts_<days>d_<timestamp>.html` and `.csv` inside `signInsLogs/`.

### Tab 3: IP Threat Searcher (Intigriti & AbuseIPDB)
- **Single IP / Bulk File (.txt)**: Inspect a single IPv4 address or load a `.txt` file containing bulk IPs (supports mixed text, newlines, and `/32` CIDR masks).
- **Check Intigriti First**: When checked, queries Intigriti (`v2/iplookup`) prior to AbuseIPDB. Any IP confirmed as authorized researcher traffic (`exists=True`) skips AbuseIPDB and is excluded from all exported files. Additionally, external IPs with an AbuseIPDB confidence score of `<= 10%` are omitted from exports so only actionable threats remain.
- **Outputs (`abuseIpLogs/`)**:
  - `abuseipdb_<name>_<timestamp>.html`: Interactive threat intelligence dashboard with metric cards (**TOTAL IPS**, **MALICIOUS**, **SUSPICIOUS**, **CLEAN**) and bold filter controls.
  - `extended_<name>_<timestamp>.csv`: Detailed CSV containing `sourceIP`, `totalReports`, `abuseConfidenceScore`, `abuseBlock`, `existsIntigriti`, and `Block?`.
  - `blocklist_<name>_<timestamp>.txt`: Ready-to-import firewall blocklist containing `IP/32` entries for actionable threats (`score > 10%`).

### Tab 4: API Keys Status
- **Refresh All Keys**: Concurrently queries AbuseIPDB using `ThreadPoolExecutor` for every key in `ABUSEIPDB_API_KEYS`.
- Displays individual status cards (`Active`, `Exhausted (429)`, `Unauthorized (401)`), remaining quota, usage percentage, UTC reset timestamp, and the total available query pool.

---

## Directory Structure & Outputs

```text
├── gui_soc_suite.py
├── README.md
├── signInsLogs/
│   ├── signins_intel_<user>_<days>d_<timestamp>.csv
│   ├── signins_intel_<user>_<days>d_<timestamp>.html
│   ├── signins_intel_bulk_<N>accounts_<days>d_<timestamp>.html
│   └── signins_intel_RISKY_<LEVEL>_<N>accounts_<days>d_<timestamp>.html
└── abuseIpLogs/
    ├── abuseipdb_<sourcefile>_<timestamp>.html
    ├── extended_<sourcefile>_<timestamp>.csv
    └── blocklist_<sourcefile>_<timestamp>.txt
```

---

## Corporate Network, Permissions & SSL Troubleshooting

- **Error `AADSTS65002` (Preauthorization required)**: Occurs if using the legacy Azure CLI Client ID (`04b07795-...`) to request `IdentityRiskyUser.Read.All`. Ensure `CLIENT_ID` is set to Microsoft Graph Command Line Tools (`14d82eec-204b-4c2f-b7e8-296a70dab67e`), or register an internal Azure AD application with delegated permissions `AuditLog.Read.All` and `IdentityRiskyUser.Read.All`.
- **Corporate SSL/TLS Proxy Inspection**: In environments performing HTTPS inspection, standard Python requests fail with `CERTIFICATE_VERIFY_FAILED`. The suite handles this natively by disabling `urllib3` warnings and setting `verify=False` on outbound API calls.
- **Data Privacy**: All authentication tokens remain in local session memory, private/internal IPs (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) are filtered locally before querying external APIs, and all generated reports are saved strictly to local disk.