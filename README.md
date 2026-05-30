# SOC Workflow Automation — Alert Enrichment

A Python automation tool that ingests simulated SIEM alerts, enriches every indicator of compromise (IP addresses, domains, file hashes) against **VirusTotal** and **AbuseIPDB** free APIs, calculates a risk score, and generates structured incident reports in three formats.

Built as a SOC analyst portfolio project demonstrating threat-intelligence automation, API integration, and incident reporting.

---

## What It Does

```
[SIEM Alert JSON]
       │
       ▼
[Extract IOCs] ─────────────────────────────────────────────┐
       │                                                     │
       ├── IP Addresses ──► VirusTotal  (malicious votes,   │
       │                    AbuseIPDB    country, ASN, ISP)  │
       │                                                     │
       ├── Domains ──────► VirusTotal  (malicious votes,    │
       │                                registrar, category) │
       │                                                     │
       └── File Hashes ──► VirusTotal  (AV detections,      │
                                        file type, SHA-256)  │
                                                             │
                      [Risk Scoring: 0–100] ◄────────────────┘
                               │
                        ┌──────┴──────┐
                        ▼             ▼
               reports/*.json   reports/*.txt   reports/*.html
           (machine-readable) (analyst review) (interactive web)
```

Private/internal IPs (RFC 1918, loopback, link-local) and syntactically invalid IP strings are automatically skipped — no wasted API quota.

---

## Project Structure

```
SOC workflow automation script/
│
├── src/
│   └── soc_enrichment.py       ← Main script (run this)
│
├── data/
│   └── sample_alerts.json      ← Simulated SIEM alerts (input)
│
├── reports/
│   ├── example_report.txt      ← Pre-generated plain-text sample
│   └── example_report.html     ← Pre-generated HTML sample
│
├── .env                        ← Your API keys (gitignored — never committed)
├── .env.example                ← API key template (safe to commit)
├── .gitignore
├── requirements.txt
└── README.md
```

---

## Quick Start

### 1 — Clone the repository

```bash
git clone https://github.com/aditya777-dev/soc-workflow-automation.git
cd soc-workflow-automation
```

### 2 — Install dependencies

```bash
pip install -r requirements.txt
```

Installs: `requests` (HTTP API calls) and `python-dotenv` (API key loading).

### 3 — Configure API keys

```bash
cp .env.example .env
```

Edit `.env`:

```
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
```

**Get free API keys:**

| Service | URL | Free Tier |
|---------|-----|-----------|
| VirusTotal | https://www.virustotal.com/gui/sign-in | 500 lookups/day, 4/minute |
| AbuseIPDB  | https://www.abuseipdb.com/register     | 1,000 checks/day |

### 4 — Run

```bash
python src/soc_enrichment.py
```

Reports are saved to `reports/` with a timestamp in the filename.

**Custom paths:**

```bash
python src/soc_enrichment.py data/my_alerts.json --output-dir /tmp/reports
```

---

## Sample Alert Format

The script accepts a JSON array. Every IOC field is optional — only present fields are enriched.

```json
[
  {
    "alert_id": "ALT-2026-001",
    "timestamp": "2026-05-30T08:15:00Z",
    "severity": "CRITICAL",
    "alert_type": "Malware C2 Communication",
    "source_host": "WORKSTATION-042",
    "source_ip": "192.168.1.42",
    "destination_ip": "185.220.101.45",
    "destination_domain": "update.microsoft-cdn.net",
    "file_hash_md5": "44d88612fea8a8f36de82e1278abb02f",
    "file_name": "system_update.exe",
    "process": "svchost.exe",
    "description": "Suspicious outbound connection to known Tor exit node",
    "rule_triggered": "TOR_EXIT_NODE_COMMUNICATION"
  }
]
```

**Supported IOC fields:**

| Field | Enriched via |
|-------|-------------|
| `source_ip` | VirusTotal + AbuseIPDB |
| `destination_ip` | VirusTotal + AbuseIPDB |
| `destination_domain` | VirusTotal |
| `file_hash_md5` | VirusTotal |

---

## Output Reports

Three files are written for every run, named `incident_report_YYYYMMDD_HHMMSS.*`:

### `*.json` — Machine-readable
Full structured output with raw API fields and verdict scores. Suitable for SIEM ingestion, ticketing-system import, or further scripting.

### `*.txt` — Plain-text analyst report
Box-formatted report with per-alert sections, IOC enrichment blocks, and risk factors. Printable and easy to attach to tickets.

### `*.html` — Interactive web report
Dark-themed HTML report with colour-coded severity/verdict badges, risk-score progress bars, and collapsible IOC detail panels. Open in any browser — no internet connection required (fully self-contained).

See [`reports/example_report.html`](reports/example_report.html) and [`reports/example_report.txt`](reports/example_report.txt) for live samples generated against the real APIs.

---

## Risk Scoring

Additive score, capped at 100:

| Signal | Points |
|--------|--------|
| IP: ≥1 VirusTotal malicious vote | +40 |
| File hash: ≥1 VirusTotal malicious vote | +40 |
| IP: AbuseIPDB confidence ≥ 75% | +30 |
| Domain: ≥1 VirusTotal malicious vote | +25 |
| IP: AbuseIPDB confidence 25–74% | +15 |

| Final Score | Verdict |
|-------------|---------|
| 0–9 | CLEAN |
| 10–39 | POTENTIALLY_SUSPICIOUS |
| 40–69 | SUSPICIOUS |
| 70–100 | MALICIOUS |

---

## Terminal Output

```
20:03:55 [INFO    ] Loaded 3 alert(s) from data\sample_alerts.json
20:03:55 [INFO    ] Note: VirusTotal free tier = 4 req/min — expect ~16 s between lookups.
20:03:55 [INFO    ] ── Processing alert 1/3: ALT-2026-001 [CRITICAL] ──
20:03:55 [INFO    ] Skipping non-public IP '192.168.1.42' (source_ip)
20:03:55 [INFO    ] [VT] Enriching IP: 185.220.101.45
20:03:56 [INFO    ] [AbuseIPDB] Checking IP: 185.220.101.45
...

==============================================================
  ENRICHMENT COMPLETE
==============================================================
  Alerts processed : 3
  JSON report      : reports\incident_report_20260530_200522.json
  Text report      : reports\incident_report_20260530_200522.txt
  HTML report      : reports\incident_report_20260530_200522.html
==============================================================

  Alert ID             Verdict                    Risk Score
  ------------------ ------------------------ ----------
  ALT-2026-001         MALICIOUS                  100/100
  ALT-2026-002         SUSPICIOUS                 40/100
  ALT-2026-003         MALICIOUS                  70/100
```

---

## Rate Limits & Timing

| Service | Free Limit | How this script handles it |
|---------|------------|---------------------------|
| VirusTotal | 4 req/min, 500/day | 16 s enforced delay between every VT call |
| AbuseIPDB | 1,000/day | No per-minute cap — called immediately |

The same IOC value across multiple alerts is queried **once** and cached for the run duration.

**Estimated runtime for the 3 sample alerts:** ~2 minutes (6 VT calls × 16 s).

---

## Bugs Fixed During Development

| # | Bug | Fix |
|---|-----|-----|
| 1 | Invalid IP strings (`not.an.ip.addr`) bypassed the private-IP guard and were sent to APIs (HTTP 400/422) | `is_valid_public_ip()` now validates with `ipaddress` and requires `is_global` |
| 2 | 429 rate-limit retry was recursive — stack overflow risk under sustained throttling | Replaced with an iterative retry loop (`VT_MAX_RETRIES = 3`) |
| 3 | Log lines appeared out-of-order (logging → stderr, print → stdout) | `logging.basicConfig(stream=sys.stdout)` + `sys.stdout.reconfigure(encoding='utf-8')` |
| 4 | Unicode box-drawing characters (`→`, `──`) in log messages crashed on Windows cp1252 console | `sys.stdout.reconfigure(encoding='utf-8', errors='replace')` before logging setup |

---

## Technologies Used

| Tool | Purpose |
|------|---------|
| Python 3.8+ | Core scripting |
| `requests` | HTTP calls to threat-intel APIs |
| `python-dotenv` | Secure API key loading |
| VirusTotal API v3 | Multi-vendor malware scanning (IPs, domains, hashes) |
| AbuseIPDB API v2 | Crowd-sourced IP abuse reputation |

---

## Author

Built as a portfolio project for a SOC Analyst role.

**Demonstrated skills:**
- REST API integration (authentication, rate limiting, error handling, retries)
- IOC extraction and enrichment automation
- Risk scoring and verdict classification
- Multi-format report generation (JSON, TXT, HTML)
- Python best practices: logging, type hints, modular OOP design, caching
- Security-aware input validation (invalid/private IP filtering)
