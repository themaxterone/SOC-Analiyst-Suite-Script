import concurrent.futures
import csv
from datetime import datetime, timedelta, timezone
import html
import ipaddress
import os
import re
import sys
import threading
import time
from tkinter import messagebox, filedialog
import customtkinter as ctk
import msal
import requests
import urllib3

# Suppress SSL warnings in corporate environments with proxy inspection
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# =========================================================================
# CONFIGURATION & OUTPUT DIRECTORIES
# =========================================================================
# Microsoft Graph Command Line Tools official public Client ID
CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
AUTHORITY = "https://login.microsoftonline.com/organizations"

SCOPES = [
    "https://graph.microsoft.com/AuditLog.Read.All",
    "https://graph.microsoft.com/IdentityRiskyUser.Read.All"
]

DIR_SIGNINS = "signInsLogs"
DIR_ABUSEIP = "abuseIpLogs"

os.makedirs(DIR_SIGNINS, exist_ok=True)
os.makedirs(DIR_ABUSEIP, exist_ok=True)

# Intigriti Access Token (Company / Researcher IP Verification)
INTIGRITI_ACCESS_TOKEN = "YOUR_INTIGRITI_ACCESS_TOKEN"
INTIGRITI_API_URL = "https://api.intigriti.com/external/company/v2/iplookup"

# AbuseIPDB API Keys Pool
ABUSEIPDB_API_KEYS = [
    "YOUR_API_KEY_1",
    "YOUR_API_KEY_2",
    "YOUR_API_KEY_3"
]
# =========================================================================

ABUSE_CATEGORIES = {
    3: "Fraud Orders", 4: "DDoS Attack", 9: "Open Proxy", 10: "Web Spam",
    11: "Email Spam", 14: "Port Scan", 15: "Hacking", 18: "Brute-Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH", 23: "IoT Targeted"
}

ENTRA_ERRORS = {
    50034: "The user account does not exist in the directory.",
    50053: "Account is temporarily locked out due to multiple failed password attempts.",
    50055: "The user's password has expired.",
    50057: "The user account is disabled.",
    50058: "Silent sign-in failed (user interaction required).",
    50074: "Multifactor authentication (MFA) is required.",
    50076: "Strong authentication (MFA) is required due to security policies.",
    50079: "The user must enroll in multifactor authentication.",
    50088: "The external user does not belong to the target tenant.",
    50126: "Invalid username or password.",
    50131: "The device does not comply with security policies or is not trusted.",
    50144: "Password has expired and must be reset.",
    53003: "Access blocked by Conditional Access policies.",
    70008: "Refresh token has expired.",
    70043: "Session revoked or terminated by the administrator."
}

IP_CACHE = {}
INTIGRITI_CACHE = {}
CURRENT_KEY_INDEX = 0

def get_current_api_key():
    global CURRENT_KEY_INDEX
    if not ABUSEIPDB_API_KEYS:
        return None
    return ABUSEIPDB_API_KEYS[CURRENT_KEY_INDEX]

def rotate_api_key(log_callback):
    global CURRENT_KEY_INDEX
    if len(ABUSEIPDB_API_KEYS) <= 1:
        return False
    CURRENT_KEY_INDEX = (CURRENT_KEY_INDEX + 1) % len(ABUSEIPDB_API_KEYS)
    log_callback(f"[!] Quota reached. Rotating to API Key #{CURRENT_KEY_INDEX + 1}...", "warn")
    return True

def get_access_token(log_callback):
    app = msal.PublicClientApplication(CLIENT_ID, authority=AUTHORITY)
    log_callback("[*] Opening browser for Microsoft interactive authentication...", "info")
    result = app.acquire_token_interactive(scopes=SCOPES, prompt="select_account")
    if "access_token" in result:
        log_callback("[+] Authentication successful.", "success")
        return result["access_token"]
    else:
        error_msg = result.get("error_description", result.get("error"))
        raise Exception(f"Authentication error: {error_msg}")

def is_public_ip(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local)
    except ValueError:
        return False

def check_intigriti_ip(ip, log_callback):
    """Queries Intigriti v2 iplookup endpoint and returns True if exists==True."""
    if ip in INTIGRITI_CACHE:
        return INTIGRITI_CACHE[ip]

    if not INTIGRITI_ACCESS_TOKEN or INTIGRITI_ACCESS_TOKEN.startswith("YOUR_INTIGRITI"):
        return False

    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {INTIGRITI_ACCESS_TOKEN.strip()}"
    }

    try:
        url = f"{INTIGRITI_API_URL}?ipAddress={ip}"
        response = requests.get(url, headers=headers, timeout=10, verify=False)

        if response.status_code == 200:
            data = response.json()
            is_match = bool(data.get("exists", False))
            INTIGRITI_CACHE[ip] = is_match
            return is_match

        elif response.status_code in (401, 403):
            log_callback(f"[!] Intigriti API unauthorized (HTTP {response.status_code}). Check INTIGRITI_ACCESS_TOKEN.", "warn")
            INTIGRITI_CACHE[ip] = False
            return False

        else:
            INTIGRITI_CACHE[ip] = False
            return False

    except Exception as e:
        log_callback(f"[!] Intigriti lookup error for {ip}: {e}", "warn")
        INTIGRITI_CACHE[ip] = False
        return False

def check_abuseipdb(ip, log_callback):
    if not ip or ip == "N/A":
        return {"score": 0, "reports": 0, "categories": [], "risk": "Unknown", "isp": "N/A", "domain": "N/A", "country": "N/A"}

    if ip in IP_CACHE:
        return IP_CACHE[ip]

    if not is_public_ip(ip):
        res = {"score": 0, "reports": 0, "categories": ["Private / Internal IP"], "risk": "Internal", "isp": "Internal Network", "domain": "N/A", "country": "Internal"}
        IP_CACHE[ip] = res
        return res

    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"}
    attempts = 0
    max_attempts = len(ABUSEIPDB_API_KEYS)

    while attempts < max_attempts:
        active_key = get_current_api_key()
        if not active_key or active_key.startswith("YOUR_API_KEY"):
            res = {"score": 0, "reports": 0, "categories": ["No API Key"], "risk": "Unknown", "isp": "N/A", "domain": "N/A", "country": "N/A"}
            IP_CACHE[ip] = res
            return res

        headers = {"Accept": "application/json", "Key": active_key}
        try:
            response = requests.get(url, headers=headers, params=params, timeout=12, verify=False)
            if response.status_code == 429:
                attempts += 1
                if rotate_api_key(log_callback) and attempts < max_attempts:
                    continue
                else:
                    res = {"score": 0, "reports": 0, "categories": ["Rate Limited (429)"], "risk": "Unknown", "isp": "N/A", "domain": "N/A", "country": "N/A"}
                    IP_CACHE[ip] = res
                    return res
            if response.status_code == 401:
                attempts += 1
                rotate_api_key(log_callback)
                continue

            response.raise_for_status()
            data = response.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            reports = data.get("totalReports", 0)
            isp = data.get("isp") or "N/A"
            domain = data.get("domain") or "N/A"
            country = data.get("countryCode") or "N/A"

            reported_cats = set()
            for r in data.get("reports", []):
                for c in r.get("categories", []):
                    reported_cats.add(c)
            cat_labels = [ABUSE_CATEGORIES.get(c, f"Category {c}") for c in reported_cats]

            risk = "Malicious" if score >= 60 else "Suspicious" if score >= 20 else "Clean"
            res = {"score": score, "reports": reports, "categories": sorted(cat_labels), "risk": risk, "isp": isp, "domain": domain, "country": country}
            time.sleep(0.12)
            IP_CACHE[ip] = res
            return res
        except Exception as e:
            res = {"score": 0, "reports": 0, "categories": [f"Error: {e}"], "risk": "Unknown", "isp": "N/A", "domain": "N/A", "country": "N/A"}
            IP_CACHE[ip] = res
            return res

    res = {"score": 0, "reports": 0, "categories": ["Lookup Failed"], "risk": "Unknown", "isp": "N/A", "domain": "N/A", "country": "N/A"}
    IP_CACHE[ip] = res
    return res

def check_single_key(key_index, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": api_key.strip()}
    params = {"ipAddress": "1.1.1.1", "maxAgeInDays": "1"}
    masked_key = f"{api_key[:6]}...{api_key[-4:]}" if len(api_key) > 10 else api_key

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10, verify=False)
        limit = response.headers.get("X-RateLimit-Limit")
        remaining = response.headers.get("X-RateLimit-Remaining")
        reset_ts = response.headers.get("X-RateLimit-Reset")

        reset_str = "N/A"
        if reset_ts and reset_ts.isdigit():
            reset_dt = datetime.fromtimestamp(int(reset_ts), tz=timezone.utc)
            reset_str = reset_dt.strftime("%Y-%m-%d %H:%M:%S UTC")

        if response.status_code == 200:
            limit_val = int(limit) if limit and limit.isdigit() else 1000
            rem_val = int(remaining) if remaining and remaining.isdigit() else 0
            used = limit_val - rem_val
            usage_pct = (used / limit_val) * 100 if limit_val > 0 else 0
            return {"index": key_index, "key": masked_key, "status": "Active", "limit": limit_val, "remaining": rem_val, "used_pct": f"{usage_pct:.1f}%", "reset": reset_str, "color": "#16a34a"}
        elif response.status_code == 429:
            return {"index": key_index, "key": masked_key, "status": "Exhausted (429)", "limit": limit or 1000, "remaining": 0, "used_pct": "100.0%", "reset": reset_str, "color": "#dc2626"}
        elif response.status_code == 401:
            return {"index": key_index, "key": masked_key, "status": "Unauthorized (401)", "limit": "-", "remaining": "-", "used_pct": "-", "reset": "-", "color": "#991b1b"}
        else:
            return {"index": key_index, "key": masked_key, "status": f"HTTP {response.status_code}", "limit": "-", "remaining": "-", "used_pct": "-", "reset": "-", "color": "#d97706"}
    except Exception as e:
        return {"index": key_index, "key": masked_key, "status": f"Error: {type(e).__name__}", "limit": "-", "remaining": "-", "used_pct": "-", "reset": "-", "color": "#d97706"}

# =========================================================================
# HTML & REPORT GENERATORS
# =========================================================================
def export_signins_html(filepath, title_label, days, records, user_summaries, use_abuseip=True):
    total = len(records)
    success_count = sum(1 for r in records if r["is_success"])
    failure_count = total - success_count
    malicious_ips = sum(1 for r in records if r.get("abuse_risk") == "Malicious")
    suspicious_ips = sum(1 for r in records if r.get("abuse_risk") == "Suspicious")
    total_users_count = len(user_summaries)

    account_summary_rows = []
    for u in user_summaries:
        account_summary_rows.append(f"""
        <tr>
            <td class="font-mono"><strong>{html.escape(u['user'])}</strong></td>
            <td><strong>{u['total']}</strong></td>
            <td style="color: var(--success); font-weight: 700;">{u['success']}</td>
            <td style="color: var(--danger); font-weight: 700;">{u['failures']}</td>
            {"<td style='color: var(--danger); font-weight: 700;'>" + str(u['malicious']) + "</td>" if use_abuseip else ""}
            {"<td style='color: var(--warning); font-weight: 700;'>" + str(u['suspicious']) + "</td>" if use_abuseip else ""}
            <td>{u['unique_ips']}</td>
            <td>
                <button class="filter-btn-sm" onclick="filterByUser('{html.escape(u['user'])}')">Filter Logs</button>
            </td>
        </tr>
        """)

    rows_html = []
    for r in records:
        status_cell = '<span class="badge badge-success">Success</span>' if r["is_success"] else f'<span class="badge badge-danger">Failure ({r["error_code"]})</span><div class="failure-desc">{html.escape(r["failure_desc"])}</div>'

        if use_abuseip:
            risk = r.get("abuse_risk", "Unknown")
            score = r.get("abuse_score", 0)
            bar_color = "#dc2626" if risk == "Malicious" else "#d97706" if risk == "Suspicious" else "#64748b" if risk == "Internal" else "#16a34a"
            badge_cls = "badge-danger" if risk == "Malicious" else "badge-warning" if risk == "Suspicious" else "badge-info" if risk == "Internal" else "badge-success"
            cats_text = ", ".join(r.get("abuse_categories", [])) if r.get("abuse_categories") else "Clean"
            ip_cell = f"""
            <div class="ip-block">
                <span class="font-mono"><strong>{html.escape(r['ip'])}</strong></span>
                <div><span class="badge {badge_cls}">{risk} ({score}%)</span> <small class="text-muted">{r.get('abuse_reports', 0)} rep.</small></div>
                <div class="progress-bar-bg"><div class="progress-bar-fill" style="width: {score}%; background-color: {bar_color};"></div></div>
                <div class="cats-tags text-muted">{html.escape(cats_text)}</div>
            </div>"""
        else:
            risk = "N/A"
            ip_cell = f'<span class="font-mono"><strong>{html.escape(r["ip"])}</strong></span>'

        rows_html.append(f"""
        <tr data-status="{r['status']}" data-risk="{risk}" data-user="{html.escape(r['user'].lower())}">
            <td class="font-mono text-nowrap">{html.escape(r['datetime'])}</td>
            <td><strong>{html.escape(r['user'])}</strong><br><small class="text-muted">{html.escape(r['user_display'])}</small></td>
            <td>{html.escape(r['app'])}</td>
            <td class="status-cell">{status_cell}</td>
            <td class="ip-cell">{ip_cell}</td>
            <td>{html.escape(r['location'])}</td>
            <td>{html.escape(r['os'])}</td>
            <td>{html.escape(r['browser'])}</td>
        </tr>""")

    abuse_cards_html = f"""
        <div class="stat-card"><span class="num" style="color: var(--danger);">{malicious_ips}</span><span class="label">Malicious IPs</span></div>
        <div class="stat-card"><span class="num" style="color: var(--warning);">{suspicious_ips}</span><span class="label">Suspicious IPs</span></div>
    """ if use_abuseip else ""

    abuse_filter_btns_html = """
        <button class="filter-btn" onclick="setFilter('Malicious', this)">Malicious IP</button>
        <button class="filter-btn" onclick="setFilter('Suspicious', this)">Suspicious IP</button>
        <button class="filter-btn" onclick="setFilter('Clean', this)">Clean IP</button>
    """ if use_abuseip else ""

    template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Sign-in Audit - {html.escape(title_label)}</title>
    <style>
        :root {{
            --bg-primary: #f8fafc; --surface: #ffffff; --text-main: #0f172a; --text-muted: #64748b;
            --border-color: #e2e8f0; --primary: #2563eb; --success: #16a34a; --danger: #dc2626;
            --warning: #d97706; --success-bg: #dcfce7; --danger-bg: #fee2e2; --warning-bg: #fef3c7; --info-bg: #e2e8f0;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: var(--bg-primary); color: var(--text-main); padding: 24px; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px; margin-bottom: 20px; }}
        .header h1 {{ font-size: 1.5rem; font-weight: 700; }}
        .header p {{ color: var(--text-muted); font-size: 0.9rem; }}
        .stats {{ display: flex; gap: 12px; flex-wrap: wrap; }}
        .stat-card {{ background: var(--surface); padding: 10px 18px; border-radius: 10px; border: 1px solid var(--border-color); display: flex; flex-direction: column; align-items: center; min-width: 90px; box-shadow: 0 1px 3px rgba(0,0,0,0.02); }}
        .stat-card .num {{ font-size: 1.5rem; font-weight: 700; }}
        .stat-card .label {{ font-size: 0.72rem; color: var(--text-muted); text-transform: uppercase; margin-top: 4px; font-weight: 700; }}

        .section-card {{
            background: var(--surface); border: 1px solid var(--border-color); border-radius: 10px;
            padding: 16px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        }}
        .section-title {{ font-size: 1.1rem; font-weight: 700; margin-bottom: 12px; }}
        .summary-table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem; }}
        .summary-table th {{ background: #f1f5f9; padding: 10px 12px; font-weight: 700; border-bottom: 1px solid var(--border-color); }}
        .summary-table td {{ padding: 10px 12px; border-bottom: 1px solid var(--border-color); }}
        .filter-btn-sm {{
            background: var(--surface); border: 1px solid var(--border-color); padding: 4px 10px;
            border-radius: 6px; font-size: 0.75rem; font-weight: 700; cursor: pointer; transition: 0.1s;
        }}
        .filter-btn-sm:hover {{ background: var(--primary); color: white; border-color: var(--primary); }}

        .controls {{ display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; align-items: center; }}
        .search-box {{ flex: 1; min-width: 250px; padding: 10px 14px; border: 1px solid var(--border-color); border-radius: 8px; font-size: 0.9rem; outline: none; background: var(--surface); }}
        .search-box:focus {{ border-color: var(--primary); }}
        .btn-filters {{ display: flex; gap: 8px; flex-wrap: wrap; }}
        .filter-btn {{
            background: var(--surface); border: 1px solid var(--border-color); padding: 8px 16px; border-radius: 8px;
            cursor: pointer; font-size: 0.85rem; font-weight: 700; color: var(--text-main); transition: all 0.15s ease;
        }}
        .filter-btn:hover {{ background: #f1f5f9; }}
        .filter-btn.active {{ background: var(--primary); color: white; border-color: var(--primary); }}

        .table-container {{ background: var(--surface); border: 1px solid var(--border-color); border-radius: 10px; overflow: auto; max-height: 75vh; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem; }}
        thead {{ position: sticky; top: 0; background: #f1f5f9; z-index: 10; }}
        th {{ padding: 12px 14px; font-weight: 700; color: #334155; border-bottom: 2px solid var(--border-color); white-space: nowrap; }}
        td {{ padding: 12px 14px; border-bottom: 1px solid var(--border-color); vertical-align: top; }}
        tr:hover {{ background-color: #f8fafc; }}
        .status-cell {{ min-width: 170px; max-width: 230px; }}
        .ip-cell {{ min-width: 200px; max-width: 280px; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 12px; font-weight: 700; font-size: 0.72rem; text-align: center; }}
        .badge-success {{ background-color: var(--success-bg); color: var(--success); }}
        .badge-danger {{ background-color: var(--danger-bg); color: var(--danger); }}
        .badge-warning {{ background-color: var(--warning-bg); color: var(--warning); }}
        .badge-info {{ background-color: var(--info-bg); color: #475569; }}
        .failure-desc {{ font-size: 0.72rem; color: #991b1b; margin-top: 5px; line-height: 1.3; background: #fef2f2; padding: 4px 6px; border-radius: 4px; border-left: 2px solid #ef4444; word-break: break-word; }}
        .ip-block {{ display: flex; flex-direction: column; gap: 4px; }}
        .progress-bar-bg {{ width: 100%; height: 6px; background-color: #e2e8f0; border-radius: 3px; overflow: hidden; margin-top: 3px; }}
        .progress-bar-fill {{ height: 100%; border-radius: 3px; }}
        .cats-tags {{ font-size: 0.72rem; line-height: 1.2; word-break: break-word; }}
        .font-mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.82rem; }}
        .text-nowrap {{ white-space: nowrap; }}
        .text-muted {{ color: var(--text-muted); }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>User Sign-in Audit Report</h1>
            <p>Target: <strong>{html.escape(title_label)}</strong> | Window: Last {days} days | Threat Intel: <strong>{'Enabled' if use_abuseip else 'Disabled'}</strong></p>
        </div>
        <div class="stats">
            <div class="stat-card"><span class="num">{total_users_count}</span><span class="label">Accounts</span></div>
            <div class="stat-card"><span class="num">{total}</span><span class="label">Total Logs</span></div>
            <div class="stat-card"><span class="num" style="color: var(--success);">{success_count}</span><span class="label">Success</span></div>
            <div class="stat-card"><span class="num" style="color: var(--danger);">{failure_count}</span><span class="label">Failures</span></div>
            {abuse_cards_html}
        </div>
    </div>

    <div class="section-card">
        <div class="section-title">Account Investigation Breakdown</div>
        <table class="summary-table">
            <thead>
                <tr>
                    <th>Account / UPN</th>
                    <th>Total Logs</th>
                    <th>Success</th>
                    <th>Failures</th>
                    {"<th>Malicious IPs</th>" if use_abuseip else ""}
                    {"<th>Suspicious IPs</th>" if use_abuseip else ""}
                    <th>Unique IPs</th>
                    <th>Quick Action</th>
                </tr>
            </thead>
            <tbody>
                {''.join(account_summary_rows)}
            </tbody>
        </table>
    </div>

    <div class="controls">
        <input type="text" id="searchInput" class="search-box" placeholder="Search by IP, user account, app, browser, date, error...">
        <div class="btn-filters">
            <button class="filter-btn active" onclick="setFilter('all', this)">All</button>
            <button class="filter-btn" onclick="setFilter('Success', this)">Success</button>
            <button class="filter-btn" onclick="setFilter('Failure', this)">Failures</button>
            {abuse_filter_btns_html}
        </div>
    </div>

    <div class="table-container">
        <table id="logsTable">
            <thead>
                <tr>
                    <th>Date and Time</th><th>User</th><th>APP</th><th>Auth Status</th>
                    <th>IP Address {'& Threat Intel' if use_abuseip else ''}</th>
                    <th>Location</th><th>OS</th><th>Device Browser</th>
                </tr>
            </thead>
            <tbody>{''.join(rows_html)}</tbody>
        </table>
    </div>

    <script>
        const searchInput = document.getElementById('searchInput');
        const rows = document.querySelectorAll('#logsTable tbody tr');
        let activeFilter = 'all';

        function applyFilters() {{
            const query = searchInput.value.toLowerCase();
            rows.forEach(row => {{
                const matchesSearch = row.innerText.toLowerCase().includes(query);
                const status = row.getAttribute('data-status');
                const risk = row.getAttribute('data-risk');
                let matchesFilter = (activeFilter === 'all') || 
                                    (activeFilter === status) || 
                                    (activeFilter === risk);
                row.style.display = (matchesSearch && matchesFilter) ? '' : 'none';
            }});
        }}

        searchInput.addEventListener('input', applyFilters);

        function setFilter(filterType, btn) {{
            activeFilter = filterType;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            applyFilters();
        }}

        function filterByUser(userEmail) {{
            searchInput.value = userEmail;
            applyFilters();
            document.getElementById('logsTable').scrollIntoView({{ behavior: 'smooth' }});
        }}
    </script>
</body>
</html>"""
    with open(filepath, mode="w", encoding="utf-8") as f:
        f.write(template)

def export_ipsearcher_blocklist_and_csv(txt_filepath, csv_filepath, results):
    """Exports IPLookup.py compatible blocklist (.txt with /32) and extended CSV (excluding Intigriti IPs)."""
    with open(txt_filepath, mode="w", newline="", encoding="utf-8") as txt_f, \
         open(csv_filepath, mode="w", newline="", encoding="utf-8-sig") as csv_f:
        
        writer = csv.writer(csv_f)
        writer.writerow(["sourceIP", "totalReports", "abuseConfidenceScore", "abuseBlock", "existsIntigriti", "Block?"])
        
        for r in results:
            if not r:
                continue
            ip = r.get("ip", "")
            score = r.get("score", 0)
            reports = r.get("reports", 0)
            
            abuse_block = score > 10
            final_block = abuse_block
            
            if final_block:
                txt_f.write(f"{ip}/32\n")
                
            writer.writerow([
                ip,
                reports,
                score,
                "TRUE" if abuse_block else "FALSE",
                "FALSE",
                "TRUE" if final_block else "FALSE"
            ])

# =========================================================================
# MODERN GUI APP
# =========================================================================
class SOCSuiteModernApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SOC Analyst Suite — V3")
        self.geometry("1000x770")
        self.minsize(820, 640)

        self.top_bar = ctk.CTkFrame(self, fg_color="transparent")
        self.top_bar.pack(fill="x", padx=20, pady=(15, 5))

        self.lbl_title = ctk.CTkLabel(self.top_bar, text="Security Operations Suite", font=ctk.CTkFont(family="Segoe UI Variable Display", size=20, weight="bold"))
        self.lbl_title.pack(side="left")

        self.theme_switch = ctk.CTkSwitch(self.top_bar, text="Dark Mode", command=self.toggle_theme)
        self.theme_switch.pack(side="right")
        if ctk.get_appearance_mode() == "Dark":
            self.theme_switch.select()

        self.tabview = ctk.CTkTabview(self, corner_radius=10)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=(5, 15))

        self.tab_signins = self.tabview.add("User Sign-ins Audit")
        self.tab_risky = self.tabview.add("Risky Users (High)")
        self.tab_ipsearch = self.tabview.add("IP Threat Searcher")
        self.tab_keys = self.tabview.add("API Keys Status")

        self.setup_tab_signins()
        self.setup_tab_risky()
        self.setup_tab_ipsearch()
        self.setup_tab_keys()

    def setup_terminal_colors(self, textbox):
        textbox.tag_config("default", foreground="#d4d4d4")
        textbox.tag_config("info", foreground="#38bdf8")
        textbox.tag_config("success", foreground="#4ade80")
        textbox.tag_config("warn", foreground="#facc15")
        textbox.tag_config("danger", foreground="#f87171")
        textbox.tag_config("header", foreground="#c084fc")
        textbox.tag_config("muted", foreground="#94a3b8")

    def write_colored(self, textbox, message, tag=None):
        if tag is None:
            if message.startswith("[+]") or "Successful" in message or "Active" in message or "Clean" in message:
                tag = "success"
            elif message.startswith("[!]") or message.startswith("[-]") or "Error" in message or "Failed" in message or "Malicious" in message:
                tag = "danger"
            elif message.startswith("[*]") or "Querying" in message or "Authenticating" in message or "Intigriti" in message:
                tag = "info"
            elif "Quota" in message or "Suspicious" in message or "Rate limit" in message or "Skipping" in message:
                tag = "warn"
            elif message.startswith("=") or message.startswith("-"):
                tag = "header"
            else:
                tag = "default"

        textbox.insert("end", message + "\n", tag)
        textbox.see("end")

    def toggle_theme(self):
        if self.theme_switch.get() == 1:
            ctk.set_appearance_mode("Dark")
        else:
            ctk.set_appearance_mode("Light")

    # ---------------------------------------------------------------------
    # TAB 1: User Sign-ins Audit (Single vs Bulk Mode)
    # ---------------------------------------------------------------------
    def setup_tab_signins(self):
        card = ctk.CTkFrame(self.tab_signins, corner_radius=10)
        card.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(card, text="Microsoft Entra ID Investigation", font=ctk.CTkFont(size=14, weight="bold")).grid(row=0, column=0, columnspan=4, sticky="w", padx=15, pady=(12, 10))

        self.user_mode_var = ctk.StringVar(value="single")

        self.rb_user_single = ctk.CTkRadioButton(card, text="Single Account:", variable=self.user_mode_var, value="single", command=self.toggle_user_inputs)
        self.rb_user_single.grid(row=1, column=0, sticky="w", padx=15, pady=5)
        self.entry_user = ctk.CTkEntry(card, placeholder_text="user@company.com", width=260)
        self.entry_user.grid(row=1, column=1, sticky="w", padx=5, pady=5)
        self.entry_user.insert(0, "user@company.com")

        self.rb_user_bulk = ctk.CTkRadioButton(card, text="Bulk File (.txt):", variable=self.user_mode_var, value="bulk", command=self.toggle_user_inputs)
        self.rb_user_bulk.grid(row=2, column=0, sticky="w", padx=15, pady=5)
        self.entry_file_users = ctk.CTkEntry(card, width=260, state="disabled")
        self.entry_file_users.grid(row=2, column=1, sticky="w", padx=5, pady=5)
        self.btn_browse_users = ctk.CTkButton(card, text="Browse", width=75, state="disabled", command=self.browse_users_file)
        self.btn_browse_users.grid(row=2, column=2, sticky="w", padx=5, pady=5)

        opt_frame = ctk.CTkFrame(card, fg_color="transparent")
        opt_frame.grid(row=3, column=0, columnspan=4, sticky="w", padx=15, pady=(8, 12))

        ctk.CTkLabel(opt_frame, text="Days to Query:").pack(side="left", padx=(0, 6))
        self.entry_days = ctk.CTkEntry(opt_frame, width=65)
        self.entry_days.pack(side="left", padx=(0, 20))
        self.entry_days.insert(0, "15")

        self.var_abuse = ctk.BooleanVar(value=True)
        self.chk_abuse = ctk.CTkCheckBox(opt_frame, text="Enrich IPs with AbuseIPDB Threat Intel", variable=self.var_abuse)
        self.chk_abuse.pack(side="left")

        self.btn_run_signins = ctk.CTkButton(card, text="Run Audit", width=130, height=36, font=ctk.CTkFont(weight="bold"), command=self.start_signins_audit)
        self.btn_run_signins.grid(row=1, column=3, rowspan=2, padx=15, pady=5, sticky="nsew")

        self.prog_signins = ctk.CTkProgressBar(self.tab_signins, corner_radius=5)
        self.prog_signins.pack(fill="x", padx=10, pady=(10, 4))
        self.prog_signins.set(0)

        self.lbl_status_signins = ctk.CTkLabel(self.tab_signins, text="Ready.", font=ctk.CTkFont(size=12, slant="italic"))
        self.lbl_status_signins.pack(anchor="w", padx=12, pady=(0, 6))

        self.txt_log_signins = ctk.CTkTextbox(self.tab_signins, font=ctk.CTkFont(family="Consolas", size=12), corner_radius=8)
        self.txt_log_signins.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.setup_terminal_colors(self.txt_log_signins)

    def toggle_user_inputs(self):
        if self.user_mode_var.get() == "single":
            self.entry_user.configure(state="normal")
            self.entry_file_users.configure(state="disabled")
            self.btn_browse_users.configure(state="disabled")
        else:
            self.entry_user.configure(state="disabled")
            self.entry_file_users.configure(state="normal")
            self.btn_browse_users.configure(state="normal")

    def browse_users_file(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self.entry_file_users.configure(state="normal")
            self.entry_file_users.delete(0, "end")
            self.entry_file_users.insert(0, path)
            self.entry_file_users.configure(state="disabled")

    def log_signins(self, msg, tag=None):
        self.write_colored(self.txt_log_signins, msg, tag)

    def start_signins_audit(self):
        mode = self.user_mode_var.get()
        target_users = []

        if mode == "single":
            single = self.entry_user.get().strip().lower()
            if not single or "@" not in single:
                messagebox.showwarning("Input Error", "Please provide a valid corporate email/UPN.")
                return
            target_users = [single]
        else:
            filepath = self.entry_file_users.get().strip()
            if not filepath or not os.path.isfile(filepath):
                messagebox.showwarning("File Error", "Please select a valid .txt file containing user accounts.")
                return
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.read().splitlines()
                seen = set()
                email_regex = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
                for line in lines:
                    found = email_regex.findall(line)
                    for item in found:
                        em = item.strip().lower()
                        if em not in seen:
                            seen.add(em)
                            target_users.append(em)
            except Exception as e:
                messagebox.showerror("File Error", f"Error reading file: {e}")
                return

            if not target_users:
                messagebox.showwarning("No Accounts", "No valid email addresses found in the provided file.")
                return

        try:
            days = int(self.entry_days.get())
        except ValueError:
            messagebox.showwarning("Input Error", "Days must be an integer.")
            return

        use_abuse = self.var_abuse.get()
        self.btn_run_signins.configure(state="disabled")
        self.txt_log_signins.delete("0.0", "end")
        self.prog_signins.set(0)

        threading.Thread(
            target=self.worker_signins_generic,
            args=(target_users, days, use_abuse, mode, self.log_signins, self.prog_signins, self.lbl_status_signins, self.btn_run_signins),
            daemon=True
        ).start()

    # ---------------------------------------------------------------------
    # TAB 2: Risky Users (High Risk) Detection & Investigation
    # ---------------------------------------------------------------------
    def setup_tab_risky(self):
        card = ctk.CTkFrame(self.tab_risky, corner_radius=10)
        card.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(
            card,
            text="Microsoft Entra ID Protection — High Risk Accounts",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", padx=15, pady=(12, 8))

        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.pack(fill="x", padx=15, pady=(0, 8))

        self.btn_scan_risky = ctk.CTkButton(
            btn_row,
            text="Scan High-Risk Users",
            width=180,
            height=34,
            font=ctk.CTkFont(weight="bold"),
            command=self.start_scan_risky
        )
        self.btn_scan_risky.pack(side="left", padx=(0, 12))

        self.btn_audit_risky = ctk.CTkButton(
            btn_row,
            text="Audit High-Risk Sign-ins",
            width=190,
            height=34,
            state="disabled",
            font=ctk.CTkFont(weight="bold"),
            fg_color="#dc2626",
            hover_color="#b91c1c",
            command=self.start_audit_risky_users
        )
        self.btn_audit_risky.pack(side="left")

        opt_row = ctk.CTkFrame(card, fg_color="transparent")
        opt_row.pack(fill="x", padx=15, pady=(0, 12))

        ctk.CTkLabel(opt_row, text="Audit Window (Days):").pack(side="left", padx=(0, 6))
        self.entry_risky_days = ctk.CTkEntry(opt_row, width=65)
        self.entry_risky_days.pack(side="left", padx=(0, 20))
        self.entry_risky_days.insert(0, "15")

        self.var_abuse_risky = ctk.BooleanVar(value=True)
        self.chk_abuse_risky = ctk.CTkCheckBox(
            opt_row,
            text="Enrich IPs with AbuseIPDB Threat Intel",
            variable=self.var_abuse_risky
        )
        self.chk_abuse_risky.pack(side="left")

        self.prog_risky = ctk.CTkProgressBar(self.tab_risky, corner_radius=5)
        self.prog_risky.pack(fill="x", padx=10, pady=(8, 4))
        self.prog_risky.set(0)

        self.lbl_status_risky = ctk.CTkLabel(
            self.tab_risky,
            text="Ready to scan for High-Risk accounts.",
            font=ctk.CTkFont(size=12, slant="italic")
        )
        self.lbl_status_risky.pack(anchor="w", padx=12, pady=(0, 6))

        self.txt_log_risky = ctk.CTkTextbox(
            self.tab_risky,
            font=ctk.CTkFont(family="Consolas", size=12),
            corner_radius=8
        )
        self.txt_log_risky.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.setup_terminal_colors(self.txt_log_risky)

        self.discovered_high_risky_users = []

    def log_risky(self, msg, tag=None):
        self.write_colored(self.txt_log_risky, msg, tag)

    def start_scan_risky(self):
        self.btn_scan_risky.configure(state="disabled")
        self.btn_audit_risky.configure(state="disabled")
        self.txt_log_risky.delete("0.0", "end")
        self.prog_risky.set(0)
        self.discovered_high_risky_users = []

        threading.Thread(target=self.worker_scan_risky, daemon=True).start()

    def worker_scan_risky(self):
        try:
            self.lbl_status_risky.configure(text="Authenticating via Microsoft Graph...")
            self.prog_risky.set(0.15)
            token = get_access_token(self.log_risky)

            self.lbl_status_risky.configure(text="Querying riskyUsers endpoint (riskLevel eq 'high')...")
            self.prog_risky.set(0.4)
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

            url = "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$filter=riskLevel eq 'high' and riskState eq 'atRisk'&$top=100"
            
            risky_users_found = []
            while url:
                resp = requests.get(url, headers=headers, verify=False)
                if resp.status_code == 404:
                    url = "https://graph.microsoft.com/v1.0/riskyUsers?$filter=riskLevel eq 'high' and riskState eq 'atRisk'&$top=100"
                    resp = requests.get(url, headers=headers, verify=False)

                resp.raise_for_status()
                data = resp.json()
                risky_users_found.extend(data.get("value", []))
                url = data.get("@odata.nextLink")

            self.prog_risky.set(1.0)

            if not risky_users_found:
                self.log_risky("\n[+] CLEAN TENANT: No users currently evaluated as High Risk (riskLevel='high', riskState='atRisk').", "success")
                self.lbl_status_risky.configure(text="Scan completed: 0 High-Risk users found.")
                messagebox.showinfo("Risky Users", "No active High-Risk users found in your tenant.")
                return

            self.discovered_high_risky_users = [
                u.get("userPrincipalName", "").strip().lower() 
                for u in risky_users_found if u.get("userPrincipalName")
            ]

            self.log_risky("\n" + "=" * 70, "header")
            self.log_risky(f"IDENTIFIED {len(self.discovered_high_risky_users)} HIGH-RISK ACCOUNT(S) IN TENANT:", "danger")
            self.log_risky("=" * 70, "header")

            for idx, u in enumerate(risky_users_found, start=1):
                upn = u.get("userPrincipalName", "N/A")
                name = u.get("userDisplayName", "N/A")
                detail = u.get("riskDetail", "N/A")
                last_upd = u.get("riskLastUpdatedDateTime", "N/A")
                self.log_risky(f"[{idx}] {upn:<35} | {name} | RiskDetail: {detail} | Updated: {last_upd}", "warn")

            self.log_risky("=" * 70, "header")
            self.log_risky("[!] Ready to run full sign-ins investigation for these accounts.\n", "info")

            self.lbl_status_risky.configure(text=f"Found {len(self.discovered_high_risky_users)} High-Risk user(s). Ready to audit.")
            self.btn_audit_risky.configure(state="normal")

            if messagebox.askyesno("High Risk Users Detected", f"Found {len(self.discovered_high_risky_users)} HIGH-RISK user(s):\n\n" + "\n".join(self.discovered_high_risky_users[:5]) + ("\n..." if len(self.discovered_high_risky_users) > 5 else "") + "\n\nDo you want to audit their sign-in logs and generate the bulk report now?"):
                self.start_audit_risky_users()

        except Exception as e:
            self.log_risky(f"\n[!] ERROR querying risky users: {e}", "danger")
            self.lbl_status_risky.configure(text="Error querying risky users.")
            messagebox.showerror("Graph Error", str(e))
        finally:
            self.btn_scan_risky.configure(state="normal")

    def start_audit_risky_users(self):
        if not self.discovered_high_risky_users:
            messagebox.showwarning("No Accounts", "Run 'Scan High-Risk Users' first.")
            return

        try:
            days = int(self.entry_risky_days.get())
        except ValueError:
            messagebox.showwarning("Input Error", "Days must be an integer.")
            return

        use_abuse = self.var_abuse_risky.get()
        self.btn_scan_risky.configure(state="disabled")
        self.btn_audit_risky.configure(state="disabled")
        self.prog_risky.set(0)

        threading.Thread(
            target=self.worker_signins_generic,
            args=(self.discovered_high_risky_users, days, use_abuse, "risky_high", self.log_risky, self.prog_risky, self.lbl_status_risky, self.btn_scan_risky),
            daemon=True
        ).start()

    # ---------------------------------------------------------------------
    # GENERIC SIGN-IN AUDIT WORKER
    # ---------------------------------------------------------------------
    def worker_signins_generic(self, target_users, days, use_abuse, mode, log_func, prog_bar, status_lbl, trigger_btn):
        try:
            total_accounts = len(target_users)
            status_lbl.configure(text="Authenticating via Microsoft Graph...")
            prog_bar.set(0.05)
            token = get_access_token(log_func)

            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
            filter_date = cutoff_date.strftime("%Y-%m-%dT%H:%M:%SZ")

            all_records_global = []
            user_summaries = []

            log_func(f"[*] Starting audit for {total_accounts} account(s) over the last {days} days...", "info")

            for user_idx, user in enumerate(target_users, start=1):
                status_lbl.configure(text=f"Auditing account {user_idx}/{total_accounts}: {user}...")
                log_func(f"\n[+] [{user_idx}/{total_accounts}] Querying Graph for: {user}...", "info")

                odata_filter = f"userPrincipalName eq '{user}' and createdDateTime ge {filter_date}"
                url = f"https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter={odata_filter}&$top=100"

                user_events = []
                while url:
                    resp = requests.get(url, headers=headers, verify=False)
                    resp.raise_for_status()
                    data = resp.json()
                    user_events.extend(data.get("value", []))
                    url = data.get("@odata.nextLink")

                log_func(f"    Downloaded {len(user_events)} sign-in event(s). Parsing...", "muted")

                user_parsed = []
                user_ips = set()
                u_success = 0
                u_failures = 0
                u_malicious = 0
                u_suspicious = 0

                for ev in user_events:
                    status_info = ev.get("status", {})
                    err_code = status_info.get("errorCode", 0)
                    is_success = (err_code == 0)
                    if is_success:
                        u_success += 1
                    else:
                        u_failures += 1

                    failure_reason_raw = status_info.get("failureReason") or ""
                    failure_desc = ENTRA_ERRORS.get(err_code, failure_reason_raw or "Unknown error.") if not is_success else ""

                    loc = ev.get("location", {})
                    city = loc.get("city") or ""
                    country = loc.get("countryOrRegion") or ""
                    location = f"{city}, {country}" if city and country else (country or city or "N/A")

                    dev = ev.get("deviceDetail", {})
                    ca_list = [f"{p.get('displayName')} ({p.get('result')})" for p in ev.get("appliedConditionalAccessPolicies", [])]
                    ip = ev.get("ipAddress", "N/A")
                    if ip and ip != "N/A":
                        user_ips.add(ip)

                    rec = {
                        "datetime": ev.get("createdDateTime", "N/A"), "user": ev.get("userPrincipalName", user),
                        "user_display": ev.get("userDisplayName", "N/A"), "app": ev.get("appDisplayName", "N/A"),
                        "status": "Success" if is_success else "Failure", "is_success": is_success,
                        "error_code": err_code, "failure_desc": failure_desc, "ip": ip, "location": location,
                        "os": dev.get("operatingSystem") or "N/A", "browser": dev.get("browser") or "N/A",
                        "ca": "; ".join(ca_list) if ca_list else "None / Not Applied"
                    }

                    if use_abuse:
                        abuse_data = check_abuseipdb(ip, log_func)
                        rec["abuse_score"] = abuse_data["score"]
                        rec["abuse_reports"] = abuse_data["reports"]
                        rec["abuse_categories"] = abuse_data["categories"]
                        rec["abuse_risk"] = abuse_data["risk"]

                        if abuse_data["risk"] == "Malicious":
                            u_malicious += 1
                        elif abuse_data["risk"] == "Suspicious":
                            u_suspicious += 1

                    user_parsed.append(rec)

                all_records_global.extend(user_parsed)

                user_summaries.append({
                    "user": user,
                    "total": len(user_parsed),
                    "success": u_success,
                    "failures": u_failures,
                    "malicious": u_malicious,
                    "suspicious": u_suspicious,
                    "unique_ips": len(user_ips)
                })

                prog_val = 0.1 + (0.75 * (user_idx / total_accounts))
                prog_bar.set(prog_val)

            if not all_records_global:
                log_func("\n[-] No sign-in logs found for the selected account(s).", "warn")
                status_lbl.configure(text="Completed: 0 logs.")
                prog_bar.set(1.0)
                messagebox.showinfo("Result", "No sign-in logs were found for the requested timeframe.")
                return

            status_lbl.configure(text="Generating single unified CSV and HTML...")
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            mode_tag = "intel" if use_abuse else "std"

            if mode == "single":
                title_label = target_users[0]
                slug = target_users[0].replace("@", "_").replace(".", "_")
                csv_file = os.path.join(DIR_SIGNINS, f"signins_{mode_tag}_{slug}_{days}d_{ts}.csv")
                html_file = os.path.join(DIR_SIGNINS, f"signins_{mode_tag}_{slug}_{days}d_{ts}.html")
            elif mode == "risky_high":
                title_label = f"HIGH-RISK Users Audit ({total_accounts} Accounts)"
                csv_file = os.path.join(DIR_SIGNINS, f"signins_{mode_tag}_HIGH_RISKY_{total_accounts}accounts_{days}d_{ts}.csv")
                html_file = os.path.join(DIR_SIGNINS, f"signins_{mode_tag}_HIGH_RISKY_{total_accounts}accounts_{days}d_{ts}.html")
            else:
                title_label = f"Bulk Audit ({total_accounts} Accounts)"
                csv_file = os.path.join(DIR_SIGNINS, f"signins_{mode_tag}_bulk_{total_accounts}accounts_{days}d_{ts}.csv")
                html_file = os.path.join(DIR_SIGNINS, f"signins_{mode_tag}_bulk_{total_accounts}accounts_{days}d_{ts}.html")

            with open(csv_file, mode="w", newline="", encoding="utf-8-sig") as f:
                fields = ["Date and Time", "User", "User Display", "APP", "Status", "ErrorCode", "Failure Meaning", "IP", "Location", "OS", "Device Browser", "Conditional Access"]
                if use_abuse:
                    fields.extend(["Abuse Score", "Abuse Reports", "Abuse Risk", "Attack Categories"])
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                for r in all_records_global:
                    row = {
                        "Date and Time": r["datetime"], "User": r["user"], "User Display": r.get("user_display", ""),
                        "APP": r["app"], "Status": r["status"], "ErrorCode": r["error_code"], "Failure Meaning": r["failure_desc"],
                        "IP": r["ip"], "Location": r["location"], "OS": r["os"],
                        "Device Browser": r["browser"], "Conditional Access": r["ca"]
                    }
                    if use_abuse:
                        row.update({
                            "Abuse Score": f"{r.get('abuse_score', 0)}%", "Abuse Reports": r.get('abuse_reports', 0),
                            "Abuse Risk": r.get('abuse_risk', 'N/A'), "Attack Categories": "; ".join(r.get('abuse_categories', []))
                        })
                    writer.writerow(row)

            export_signins_html(html_file, title_label, days, all_records_global, user_summaries, use_abuseip=use_abuse)

            log_func("\n" + "=" * 65, "header")
            log_func(f"AUDIT SUMMARY — {title_label} ({days} DAYS):", "info")
            log_func(f" Accounts Queried : {total_accounts}")
            log_func(f" Total Logins     : {len(all_records_global)}")
            log_func(f" Successful       : {sum(1 for r in all_records_global if r['is_success'])}", "success")
            log_func(f" Failed           : {sum(1 for r in all_records_global if not r['is_success'])}", "danger")
            if use_abuse:
                log_func(f" Unique IPs Pool  : {len(IP_CACHE)} IPs checked", "warn")
            log_func(f"[+] Unified CSV   : {csv_file}", "success")
            log_func(f"[+] Unified HTML  : {html_file}", "success")
            log_func("=" * 65, "header")

            status_lbl.configure(text="Audit completed successfully.")
            prog_bar.set(1.0)

            if messagebox.askyesno("Complete", f"Audit finished successfully for {total_accounts} account(s).\n\nOpen HTML report in browser?"):
                os.startfile(os.path.abspath(html_file))

        except Exception as e:
            log_func(f"\n[!] ERROR: {e}", "danger")
            status_lbl.configure(text="Error occurred.")
            messagebox.showerror("Execution Error", str(e))
        finally:
            trigger_btn.configure(state="normal")
            if hasattr(self, 'btn_audit_risky'):
                self.btn_audit_risky.configure(state="normal" if self.discovered_high_risky_users else "disabled")

    # ---------------------------------------------------------------------
    # TAB 3: IP Threat Searcher (Intigriti Exclusion + AbuseIPDB + Exports)
    # ---------------------------------------------------------------------
    def setup_tab_ipsearch(self):
        card = ctk.CTkFrame(self.tab_ipsearch, corner_radius=10)
        card.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(card, text="IP Reputation & Intelligence Lookup", font=ctk.CTkFont(size=14, weight="bold")).grid(row=0, column=0, columnspan=4, sticky="w", padx=15, pady=(12, 10))

        self.ip_mode_var = ctk.StringVar(value="single")

        self.rb_single = ctk.CTkRadioButton(card, text="Single IP:", variable=self.ip_mode_var, value="single", command=self.toggle_ip_inputs)
        self.rb_single.grid(row=1, column=0, sticky="w", padx=15, pady=5)
        self.entry_single_ip = ctk.CTkEntry(card, width=200)
        self.entry_single_ip.grid(row=1, column=1, sticky="w", padx=5, pady=5)
        self.entry_single_ip.insert(0, "8.8.8.8")

        self.rb_bulk = ctk.CTkRadioButton(card, text="Bulk File (.txt):", variable=self.ip_mode_var, value="bulk", command=self.toggle_ip_inputs)
        self.rb_bulk.grid(row=2, column=0, sticky="w", padx=15, pady=5)
        self.entry_file_path = ctk.CTkEntry(card, width=320, state="disabled")
        self.entry_file_path.grid(row=2, column=1, sticky="w", padx=5, pady=5)

        self.btn_browse = ctk.CTkButton(card, text="Browse", width=80, state="disabled", command=self.browse_file)
        self.btn_browse.grid(row=2, column=2, sticky="w", padx=5, pady=5)

        self.var_intigriti_ipsearch = ctk.BooleanVar(value=True)
        self.chk_intigriti_ipsearch = ctk.CTkCheckBox(
            card,
            text="Check Intigriti first (skip AbuseIPDB & omit from export if exists)",
            variable=self.var_intigriti_ipsearch
        )
        self.chk_intigriti_ipsearch.grid(row=3, column=0, columnspan=3, sticky="w", padx=15, pady=(6, 12))

        self.btn_run_ipsearch = ctk.CTkButton(card, text="Search IP Intel", width=140, height=36, font=ctk.CTkFont(weight="bold"), command=self.start_ip_search)
        self.btn_run_ipsearch.grid(row=1, column=3, rowspan=2, padx=15, pady=5, sticky="nsew")

        self.prog_ip = ctk.CTkProgressBar(self.tab_ipsearch, corner_radius=5)
        self.prog_ip.pack(fill="x", padx=10, pady=(10, 4))
        self.prog_ip.set(0)

        self.lbl_status_ip = ctk.CTkLabel(self.tab_ipsearch, text="Ready.", font=ctk.CTkFont(size=12, slant="italic"))
        self.lbl_status_ip.pack(anchor="w", padx=12, pady=(0, 6))

        self.txt_log_ip = ctk.CTkTextbox(self.tab_ipsearch, font=ctk.CTkFont(family="Consolas", size=12), corner_radius=8)
        self.txt_log_ip.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.setup_terminal_colors(self.txt_log_ip)

    def toggle_ip_inputs(self):
        if self.ip_mode_var.get() == "single":
            self.entry_single_ip.configure(state="normal")
            self.entry_file_path.configure(state="disabled")
            self.btn_browse.configure(state="disabled")
        else:
            self.entry_single_ip.configure(state="disabled")
            self.entry_file_path.configure(state="normal")
            self.btn_browse.configure(state="normal")

    def browse_file(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self.entry_file_path.configure(state="normal")
            self.entry_file_path.delete(0, "end")
            self.entry_file_path.insert(0, path)
            self.entry_file_path.configure(state="disabled")

    def log_ip(self, msg, tag=None):
        self.write_colored(self.txt_log_ip, msg, tag)

    def start_ip_search(self):
        mode = self.ip_mode_var.get()
        if mode == "single":
            target = self.entry_single_ip.get().strip()
            if not target:
                messagebox.showwarning("Input Error", "Please provide a target IP address.")
                return
        else:
            target = self.entry_file_path.get().strip()
            if not target or not os.path.isfile(target):
                messagebox.showwarning("File Error", "Please select a valid .txt file.")
                return

        use_intigriti = self.var_intigriti_ipsearch.get()
        self.btn_run_ipsearch.configure(state="disabled")
        self.txt_log_ip.delete("0.0", "end")
        self.prog_ip.set(0)

        threading.Thread(target=self.worker_ip_search, args=(mode, target, use_intigriti), daemon=True).start()

    def worker_ip_search(self, mode, target, use_intigriti):
        try:
            if mode == "single":
                self.log_ip(f"[*] Evaluating IP: {target} (Check Intigriti first: {use_intigriti})...", "info")
                self.lbl_status_ip.configure(text="Querying IP...")
                self.prog_ip.set(0.3)

                if use_intigriti and check_intigriti_ip(target, self.log_ip):
                    self.prog_ip.set(1.0)
                    self.log_ip("\n" + "=" * 55, "header")
                    self.log_ip(f" RESULT: {target} — INTIGRITI VERIFIED", "info")
                    self.log_ip("=" * 55, "header")
                    self.log_ip(" Intigriti   : YES (exists=True)", "info")
                    self.log_ip(" Action      : Skipping AbuseIPDB & excluding from exports.", "warn")
                    self.log_ip("=" * 55 + "\n", "header")
                    self.lbl_status_ip.configure(text="Intigriti IP verified (skipped AbuseIPDB).")
                    return

                res = check_abuseipdb(target, self.log_ip)
                self.prog_ip.set(1.0)

                self.log_ip("\n" + "=" * 55, "header")
                self.log_ip(f" RESULT: {target}", "info")
                self.log_ip("=" * 55, "header")
                if use_intigriti:
                    self.log_ip(" Intigriti   : No (exists=False)")
                self.log_ip(f" Country     : {res.get('country', 'N/A')}")
                self.log_ip(f" ISP         : {res.get('isp', 'N/A')}")
                self.log_ip(f" Domain      : {res.get('domain', 'N/A')}")
                self.log_ip(f" Reports     : {res.get('reports', 0)} (90 days)")
                
                risk = res.get('risk', 'Clean')
                color_tag = "danger" if risk == "Malicious" else "warn" if risk == "Suspicious" else "success"
                self.log_ip(f" Risk / Score: {res.get('score', 0)}% ({risk})", color_tag)
                self.log_ip(f" Categories  : {', '.join(res.get('categories', [])) if res.get('categories') else 'None'}")
                self.log_ip("=" * 55 + "\n", "header")
                self.lbl_status_ip.configure(text="Lookup completed.")
            else:
                self.log_ip(f"[*] Parsing target IPs from: {target}...", "info")
                with open(target, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                ip_regex = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
                raw_ips = ip_regex.findall(content)
                seen = set()
                ips = [x for x in raw_ips if not (x in seen or seen.add(x))]

                if not ips:
                    self.log_ip("[-] No valid IPv4 addresses detected.", "danger")
                    self.lbl_status_ip.configure(text="No IPs found.")
                    return

                total_ips = len(ips)
                self.log_ip(f"[+] Found {total_ips} unique IP(s). Starting check (Intigriti first: {use_intigriti})...\n", "success")

                results = []
                skipped_intigriti = 0

                for idx, ip in enumerate(ips, start=1):
                    # 1. Comprobar primero en Intigriti; si existe, omitir AbuseIPDB y excluir del export
                    if use_intigriti and check_intigriti_ip(ip, self.log_ip):
                        skipped_intigriti += 1
                        self.log_ip(f"[{idx}/{total_ips}] {ip:<15} -> Intigriti IP (exists=True) | Skipped AbuseIPDB & omitted from export", "info")
                        self.prog_ip.set(idx / total_ips)
                        self.lbl_status_ip.configure(text=f"Processed ({idx}/{total_ips})...")
                        continue

                    # 2. Consultar en AbuseIPDB si no es de Intigriti
                    res = check_abuseipdb(ip, self.log_ip)
                    results.append({"ip": ip, **res})
                    
                    risk = res.get('risk', 'Clean')
                    color_tag = "danger" if risk == "Malicious" else "warn" if risk == "Suspicious" else "success"
                    self.log_ip(f"[{idx}/{total_ips}] {ip:<15} -> {res.get('score', 0)}% ({risk})", color_tag)
                    
                    self.prog_ip.set(idx / total_ips)
                    self.lbl_status_ip.configure(text=f"Processed ({idx}/{total_ips})...")

                if not results:
                    self.log_ip("\n" + "=" * 60, "header")
                    self.log_ip(f" BULK FINISHED | All {skipped_intigriti} IP(s) belonged to Intigriti.", "info")
                    self.log_ip(" No external IPs left to export.", "warn")
                    self.log_ip("=" * 60, "header")
                    self.lbl_status_ip.configure(text="Completed (all IPs skipped via Intigriti).")
                    messagebox.showinfo("Complete", f"All {skipped_intigriti} IP(s) matched Intigriti.\n\nNo reports were exported.")
                    return

                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                base_name = os.path.splitext(os.path.basename(target))[0]
                html_file = os.path.join(DIR_ABUSEIP, f"abuseipdb_{base_name}_{ts}.html")
                txt_block_file = os.path.join(DIR_ABUSEIP, f"blocklist_{base_name}_{ts}.txt")
                csv_ext_file = os.path.join(DIR_ABUSEIP, f"extended_{base_name}_{ts}.csv")

                export_ipsearcher_html(html_file, results, skipped_intigriti_count=skipped_intigriti)
                export_ipsearcher_blocklist_and_csv(txt_block_file, csv_ext_file, results)

                self.log_ip("\n" + "=" * 60, "header")
                self.log_ip(f" BULK FINISHED | INPUT IPs: {total_ips}", "info")
                if use_intigriti:
                    self.log_ip(f" Excluded (Intigriti) : {skipped_intigriti} IP(s) omitted", "warn")
                self.log_ip(f" Exported (AbuseIPDB) : {len(results)} IP(s)", "success")
                self.log_ip(f"[+] HTML Dashboard    : {html_file}", "success")
                self.log_ip(f"[+] Extended CSV      : {csv_ext_file}", "success")
                self.log_ip(f"[+] Blocklist TXT     : {txt_block_file}", "success")
                self.log_ip("=" * 60, "header")

                self.lbl_status_ip.configure(text="Bulk analysis completed.")
                if messagebox.askyesno("Complete", f"Bulk lookup finished.\nExported {len(results)} IP(s) (Omitted {skipped_intigriti} Intigriti IP(s)).\n\nOpen HTML report in browser?"):
                    os.startfile(os.path.abspath(html_file))
        except Exception as e:
            self.log_ip(f"\n[!] ERROR: {e}", "danger")
            self.lbl_status_ip.configure(text="Error occurred.")
            messagebox.showerror("Error", str(e))
        finally:
            self.btn_run_ipsearch.configure(state="normal")

    # ---------------------------------------------------------------------
    # TAB 4: API Keys Status Monitor
    # ---------------------------------------------------------------------
    def setup_tab_keys(self):
        card = ctk.CTkFrame(self.tab_keys, corner_radius=10)
        card.pack(fill="x", padx=10, pady=10)

        self.btn_check_keys = ctk.CTkButton(card, text="Refresh All Keys", width=150, height=34, font=ctk.CTkFont(weight="bold"), command=self.start_check_keys)
        self.btn_check_keys.pack(side="left", padx=15, pady=12)

        self.lbl_total_pool = ctk.CTkLabel(card, text="Available Pool: Not checked yet", font=ctk.CTkFont(size=14, weight="bold"), text_color="#0067c0")
        self.lbl_total_pool.pack(side="left", padx=15)

        self.prog_keys = ctk.CTkProgressBar(self.tab_keys, corner_radius=5)
        self.prog_keys.pack(fill="x", padx=10, pady=(10, 4))
        self.prog_keys.set(0)

        self.lbl_status_keys = ctk.CTkLabel(self.tab_keys, text="Click 'Refresh All Keys' to query AbuseIPDB.", font=ctk.CTkFont(size=12, slant="italic"))
        self.lbl_status_keys.pack(anchor="w", padx=12, pady=(0, 6))

        self.keys_scroll = ctk.CTkScrollableFrame(self.tab_keys, corner_radius=8)
        self.keys_scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def start_check_keys(self):
        if not ABUSEIPDB_API_KEYS:
            messagebox.showwarning("No Keys", "No API keys configured.")
            return

        self.btn_check_keys.configure(state="disabled")
        for child in self.keys_scroll.winfo_children():
            child.destroy()

        self.prog_keys.set(0)
        self.lbl_status_keys.configure(text="Checking keys concurrently...")
        threading.Thread(target=self.worker_check_keys, daemon=True).start()

    def worker_check_keys(self):
        try:
            total_keys = len(ABUSEIPDB_API_KEYS)
            results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                future_to_key = {executor.submit(check_single_key, idx, key): idx for idx, key in enumerate(ABUSEIPDB_API_KEYS, start=1)}
                for i, future in enumerate(concurrent.futures.as_completed(future_to_key), start=1):
                    results.append(future.result())
                    self.prog_keys.set(i / total_keys)

            results.sort(key=lambda x: x["index"])
            total_rem = 0
            total_lim = 0

            for r in results:
                k_card = ctk.CTkFrame(self.keys_scroll, corner_radius=8)
                k_card.pack(fill="x", pady=4, padx=5)

                ctk.CTkLabel(k_card, text=f"Key #{r['index']}: {r['key']}", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=12, pady=10)
                ctk.CTkLabel(k_card, text=r['status'], text_color=r['color'], font=ctk.CTkFont(weight="bold")).pack(side="left", padx=10)
                ctk.CTkLabel(k_card, text=f"Remaining: {r['remaining']} / {r['limit']} ({r['used_pct']} used)").pack(side="left", padx=10)
                ctk.CTkLabel(k_card, text=f"Reset: {r['reset']}", text_color="gray").pack(side="right", padx=12)

                if isinstance(r["remaining"], int) and isinstance(r["limit"], int):
                    total_rem += r["remaining"]
                    total_lim += r["limit"]

            self.lbl_total_pool.configure(text=f"Available Pool: {total_rem} / {total_lim} queries")
            self.lbl_status_keys.configure(text="Key check complete.")
        except Exception as e:
            self.lbl_status_keys.configure(text="Error checking keys.")
            messagebox.showerror("Error", str(e))
        finally:
            self.btn_check_keys.configure(state="normal")

if __name__ == "__main__":
    app = SOCSuiteModernApp()
    app.mainloop()