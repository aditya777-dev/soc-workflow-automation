#!/usr/bin/env python3
"""
SOC Workflow Automation — Alert Enrichment Script
==================================================
Ingests simulated SIEM alerts (JSON), enriches every indicator of compromise
(IPs, domains, file hashes) via VirusTotal v3 and AbuseIPDB v2, calculates a
risk score, and generates three report formats:
  • JSON  — machine-readable, suitable for SIEM ingestion
  • TXT   — formatted plain-text for analyst review
  • HTML  — interactive web report with colour-coded verdicts

Usage:
    python src/soc_enrichment.py                          # uses defaults
    python src/soc_enrichment.py data/my_alerts.json      # custom input
    python src/soc_enrichment.py --output-dir /tmp/out    # custom output dir

API keys are loaded from a .env file or environment variables:
    VIRUSTOTAL_API_KEY
    ABUSEIPDB_API_KEY
"""

import html as html_lib
import json
import os
import sys
import time
import logging
import ipaddress
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List

import requests
from dotenv import load_dotenv

# Load API keys from .env file (if present) before reading env vars
load_dotenv()

# Force UTF-8 output on Windows (PowerShell defaults to cp1252 which can't
# encode the box-drawing / arrow characters used in log messages).
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY: str  = os.getenv("ABUSEIPDB_API_KEY", "")

VT_BASE_URL       = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"

# VirusTotal free tier: 4 requests/minute.
# 16-second gap keeps us safely under the limit.
VT_REQUEST_DELAY_SECONDS = 16
VT_MAX_RETRIES           = 3   # max 429-retry attempts before giving up

# ---------------------------------------------------------------------------
# Logging — stdout so it interleaves correctly with print() output
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def is_valid_public_ip(ip: str) -> bool:
    """Return True only if `ip` is a syntactically valid, globally routable address.

    Rejects: private (RFC 1918), loopback, link-local, multicast, reserved,
    and any string that is not a valid IPv4/IPv6 address at all.
    Invalid strings previously bypassed the private-IP guard and caused
    HTTP 400/422 errors from the threat-intel APIs.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global and not addr.is_multicast
    except ValueError:
        return False


def safe_get(data: Any, *keys: str, default: Any = None) -> Any:
    """Safely navigate a nested dictionary without raising KeyError."""
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
    return current


def esc(value: Any) -> str:
    """HTML-escape a value for safe embedding in report templates."""
    return html_lib.escape(str(value) if value is not None else "")


# ---------------------------------------------------------------------------
# VirusTotal API client
# ---------------------------------------------------------------------------

class VirusTotalClient:
    """Wraps VirusTotal API v3 for IPs, domains, and file hashes.

    Free tier: 4 requests/minute (500/day).
    Enforces a minimum inter-request delay and retries 429s iteratively
    (not recursively, to avoid stack overflow under sustained rate-limiting).
    """

    def __init__(self, api_key: str) -> None:
        self.headers = {"x-apikey": api_key}
        self._last_call_time: float = 0.0

    def _get(self, url: str) -> Optional[Dict]:
        """Rate-limited GET — returns parsed JSON or None on any failure."""
        for attempt in range(1, VT_MAX_RETRIES + 1):
            # Enforce minimum gap between requests
            elapsed = time.time() - self._last_call_time
            if elapsed < VT_REQUEST_DELAY_SECONDS:
                time.sleep(VT_REQUEST_DELAY_SECONDS - elapsed)

            try:
                response = requests.get(url, headers=self.headers, timeout=15)
                self._last_call_time = time.time()

                if response.status_code == 200:
                    return response.json()

                if response.status_code == 404:
                    return None  # not in VT database — unknown, not necessarily clean

                if response.status_code == 429:
                    if attempt < VT_MAX_RETRIES:
                        log.warning(
                            f"VirusTotal rate limit hit (attempt {attempt}/{VT_MAX_RETRIES})"
                            f" — waiting 60s before retry..."
                        )
                        time.sleep(60)
                        continue
                    log.error("VirusTotal rate limit persists after max retries.")
                    return None

                log.error(f"VirusTotal HTTP {response.status_code}: {url}")
                return None

            except requests.exceptions.Timeout:
                log.error(f"VirusTotal request timed out: {url}")
                return None
            except requests.exceptions.RequestException as exc:
                log.error(f"VirusTotal request failed: {exc}")
                return None

        return None

    # -- Public enrichment methods ------------------------------------------

    def enrich_ip(self, ip: str) -> Dict:
        log.info(f"[VT] Enriching IP: {ip}")
        data = self._get(f"{VT_BASE_URL}/ip_addresses/{ip}")
        if data is None:
            return {"status": "not_found"}
        attrs = safe_get(data, "data", "attributes", default={})
        stats = safe_get(attrs, "last_analysis_stats", default={})
        return {
            "status": "found",
            "malicious_votes":   stats.get("malicious",   0),
            "suspicious_votes":  stats.get("suspicious",  0),
            "harmless_votes":    stats.get("harmless",    0),
            "undetected_votes":  stats.get("undetected",  0),
            "country":           attrs.get("country",     "Unknown"),
            "asn":               attrs.get("asn",         "Unknown"),
            "as_owner":          attrs.get("as_owner",    "Unknown"),
            "reputation":        attrs.get("reputation",  0),
            "tags":              attrs.get("tags",        []),
        }

    def enrich_domain(self, domain: str) -> Dict:
        log.info(f"[VT] Enriching domain: {domain}")
        data = self._get(f"{VT_BASE_URL}/domains/{domain}")
        if data is None:
            return {"status": "not_found"}
        attrs = safe_get(data, "data", "attributes", default={})
        stats = safe_get(attrs, "last_analysis_stats", default={})
        return {
            "status": "found",
            "malicious_votes":   stats.get("malicious",   0),
            "suspicious_votes":  stats.get("suspicious",  0),
            "harmless_votes":    stats.get("harmless",    0),
            "undetected_votes":  stats.get("undetected",  0),
            "registrar":         attrs.get("registrar",   "Unknown"),
            "reputation":        attrs.get("reputation",  0),
            "categories":        attrs.get("categories",  {}),
            "tags":              attrs.get("tags",        []),
        }

    def enrich_hash(self, file_hash: str) -> Dict:
        log.info(f"[VT] Enriching hash: {file_hash}")
        data = self._get(f"{VT_BASE_URL}/files/{file_hash}")
        if data is None:
            return {"status": "not_found"}
        attrs = safe_get(data, "data", "attributes", default={})
        stats = safe_get(attrs, "last_analysis_stats", default={})
        return {
            "status": "found",
            "malicious_votes":   stats.get("malicious",    0),
            "suspicious_votes":  stats.get("suspicious",   0),
            "harmless_votes":    stats.get("harmless",     0),
            "undetected_votes":  stats.get("undetected",   0),
            "file_type":         attrs.get("type_description", "Unknown"),
            "file_size_bytes":   attrs.get("size",             0),
            "meaningful_name":   attrs.get("meaningful_name",  "Unknown"),
            "sha256":            attrs.get("sha256",           ""),
            "md5":               attrs.get("md5",              ""),
            "tags":              attrs.get("tags",             []),
            "first_seen_utc":    attrs.get("first_submission_date"),
            "times_submitted":   attrs.get("times_submitted",  0),
        }


# ---------------------------------------------------------------------------
# AbuseIPDB API client
# ---------------------------------------------------------------------------

class AbuseIPDBClient:
    """Wraps AbuseIPDB API v2 IP-check calls.

    Free tier: 1,000 checks/day, no per-minute cap.
    """

    def __init__(self, api_key: str) -> None:
        self.headers = {"Key": api_key, "Accept": "application/json"}

    def enrich_ip(self, ip: str) -> Dict:
        log.info(f"[AbuseIPDB] Checking IP: {ip}")
        try:
            response = requests.get(
                f"{ABUSEIPDB_BASE_URL}/check",
                headers=self.headers,
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                timeout=15,
            )
            if response.status_code == 200:
                d = response.json().get("data", {})
                return {
                    "status":                "found",
                    "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
                    "total_reports":          d.get("totalReports",        0),
                    "distinct_users":         d.get("numDistinctUsers",    0),
                    "country_code":           d.get("countryCode",         "Unknown"),
                    "isp":                    d.get("isp",                 "Unknown"),
                    "usage_type":             d.get("usageType",           "Unknown"),
                    "is_whitelisted":         d.get("isWhitelisted",       False),
                    "last_reported_at":       d.get("lastReportedAt"),
                }
            if response.status_code == 429:
                log.warning("AbuseIPDB daily limit reached.")
                return {"status": "rate_limited"}
            log.error(f"AbuseIPDB HTTP {response.status_code}")
            return {"status": "error", "http_code": response.status_code}
        except requests.exceptions.Timeout:
            log.error(f"AbuseIPDB request timed out for {ip}")
            return {"status": "error", "message": "timeout"}
        except requests.exceptions.RequestException as exc:
            log.error(f"AbuseIPDB request failed: {exc}")
            return {"status": "error", "message": str(exc)}


# ---------------------------------------------------------------------------
# Alert Enrichment Engine
# ---------------------------------------------------------------------------

class AlertEnrichmentEngine:
    """Orchestrates IOC extraction and enrichment for a list of SIEM alerts.

    Caches results so the same IOC is never queried more than once per run.
    """

    def __init__(self, vt_api_key: str, abuse_api_key: str) -> None:
        self.vt    = VirusTotalClient(vt_api_key)
        self.abuse = AbuseIPDBClient(abuse_api_key)
        self._cache: Dict[str, Any] = {}

    def _cached(self, key: str, fn, *args) -> Any:
        if key not in self._cache:
            self._cache[key] = fn(*args)
        return self._cache[key]

    def enrich_alert(self, alert: Dict) -> Dict:
        enrichment: Dict[str, Any] = {"ips": {}, "domains": {}, "hashes": {}}

        # IPs — skip private, loopback, link-local, and syntactically invalid strings
        for field in ("source_ip", "destination_ip"):
            ip = alert.get(field)
            if not ip:
                continue
            if not is_valid_public_ip(ip):
                log.info(f"Skipping non-public IP {ip!r} ({field})")
                continue
            if ip not in enrichment["ips"]:
                enrichment["ips"][ip] = {
                    "field":      field,
                    "virustotal": self._cached(f"vt:ip:{ip}",    self.vt.enrich_ip,    ip),
                    "abuseipdb":  self._cached(f"abuse:ip:{ip}", self.abuse.enrich_ip, ip),
                }

        # Domain
        domain = alert.get("destination_domain")
        if domain:
            enrichment["domains"][domain] = {
                "virustotal": self._cached(
                    f"vt:domain:{domain}", self.vt.enrich_domain, domain
                ),
            }

        # File hash
        file_hash = alert.get("file_hash_md5")
        if file_hash:
            enrichment["hashes"][file_hash] = {
                "virustotal": self._cached(
                    f"vt:hash:{file_hash}", self.vt.enrich_hash, file_hash
                ),
            }

        return {
            "alert":      alert,
            "enrichment": enrichment,
            "verdict":    self._score(enrichment),
        }

    def _score(self, enrichment: Dict) -> Dict:
        """
        Additive risk score (0–100):
          +40  IP with ≥1 VT malicious vote
          +40  file hash with ≥1 VT malicious vote
          +30  IP with AbuseIPDB confidence ≥75 %
          +25  domain with ≥1 VT malicious vote
          +15  IP with AbuseIPDB confidence 25–74 %
        """
        score   = 0
        factors: List[str] = []

        for ip, data in enrichment["ips"].items():
            vt = data.get("virustotal", {})
            if vt.get("malicious_votes", 0) > 0:
                score += 40
                factors.append(
                    f"IP {ip}: {vt['malicious_votes']} VirusTotal malicious detection(s)"
                )
            abuse      = data.get("abuseipdb", {})
            confidence = abuse.get("abuse_confidence_score", 0)
            if confidence >= 75:
                score += 30
                factors.append(
                    f"IP {ip}: AbuseIPDB confidence {confidence}%"
                    f" ({abuse.get('total_reports', 0)} reports)"
                )
            elif confidence >= 25:
                score += 15
                factors.append(f"IP {ip}: AbuseIPDB confidence {confidence}%")

        for domain, data in enrichment["domains"].items():
            vt = data.get("virustotal", {})
            if vt.get("malicious_votes", 0) > 0:
                score += 25
                factors.append(
                    f"Domain {domain}: {vt['malicious_votes']} VirusTotal malicious detection(s)"
                )

        for file_hash, data in enrichment["hashes"].items():
            vt = data.get("virustotal", {})
            if vt.get("malicious_votes", 0) > 0:
                score += 40
                factors.append(
                    f"Hash {file_hash}: {vt['malicious_votes']} VirusTotal malicious detection(s)"
                )

        score = min(score, 100)
        if score >= 70:
            verdict = "MALICIOUS"
        elif score >= 40:
            verdict = "SUSPICIOUS"
        elif score >= 10:
            verdict = "POTENTIALLY_SUSPICIOUS"
        else:
            verdict = "CLEAN"

        return {"risk_score": score, "verdict": verdict, "risk_factors": factors}


# ---------------------------------------------------------------------------
# Report generator  (JSON + TXT + HTML)
# ---------------------------------------------------------------------------

class ReportGenerator:
    """Writes enrichment results to timestamped JSON, TXT, and HTML files."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self, enriched_alerts: list, timestamp: str
    ) -> Tuple[Path, Path, Path]:
        base = self.output_dir / f"incident_report_{timestamp}"

        json_path = base.with_suffix(".json")
        text_path = base.with_suffix(".txt")
        html_path = base.with_suffix(".html")

        report_payload = {
            "report_generated_utc": datetime.now(timezone.utc).isoformat(),
            "total_alerts": len(enriched_alerts),
            "alerts": enriched_alerts,
        }
        json_path.write_text(
            json.dumps(report_payload, indent=2, default=str), encoding="utf-8"
        )
        log.info(f"JSON report  → {json_path}")

        text_path.write_text(self._build_text_report(enriched_alerts), encoding="utf-8")
        log.info(f"Text report  → {text_path}")

        html_path.write_text(self._build_html_report(enriched_alerts), encoding="utf-8")
        log.info(f"HTML report  → {html_path}")

        return json_path, text_path, html_path

    # -------------------------------------------------------------------------
    # Text report
    # -------------------------------------------------------------------------

    def _build_text_report(self, enriched_alerts: list) -> str:
        W     = 78
        lines: List[str] = []
        now   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        lines += ["=" * W,
                  "  SOC WORKFLOW AUTOMATION — INCIDENT ENRICHMENT REPORT",
                  f"  Generated : {now}",
                  "=" * W, ""]

        sev_counts: Dict[str, int] = {}
        for ea in enriched_alerts:
            s = ea["alert"].get("severity", "UNKNOWN")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        total_ips     = sum(len(ea["enrichment"]["ips"])     for ea in enriched_alerts)
        total_domains = sum(len(ea["enrichment"]["domains"]) for ea in enriched_alerts)
        total_hashes  = sum(len(ea["enrichment"]["hashes"])  for ea in enriched_alerts)

        lines += ["EXECUTIVE SUMMARY", "-" * 40,
                  f"  Total Alerts Processed  : {len(enriched_alerts)}"]
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if sev_counts.get(level, 0):
                lines.append(f"  {level:<24}: {sev_counts[level]}")
        lines += [f"  IPs Enriched            : {total_ips}",
                  f"  Domains Enriched        : {total_domains}",
                  f"  File Hashes Enriched    : {total_hashes}", ""]

        for i, ea in enumerate(enriched_alerts, 1):
            alert   = ea["alert"]
            verdict = ea["verdict"]

            lines += ["=" * W,
                      (f"  ALERT {i}: {alert.get('alert_id', 'N/A')}"
                       f"  |  Severity: {alert.get('severity', 'N/A')}"
                       f"  |  Verdict: {verdict['verdict']}"
                       f"  (Risk: {verdict['risk_score']}/100)"),
                      "=" * W,
                      f"  Alert Type  : {alert.get('alert_type', 'N/A')}",
                      f"  Timestamp   : {alert.get('timestamp',  'N/A')}",
                      f"  Source      : {alert.get('source_host','N/A')}"
                      f" [{alert.get('source_ip', 'N/A')}]",
                      f"  Destination : {alert.get('destination_ip', 'N/A')}"]
            if alert.get("destination_domain"):
                lines.append(f"  Domain      : {alert['destination_domain']}")
            if alert.get("file_name"):
                lines.append(f"  File        : {alert['file_name']}"
                             f" (MD5: {alert.get('file_hash_md5','N/A')})")
            if alert.get("process"):
                lines.append(f"  Process     : {alert['process']}")
            lines += [f"  Description : {alert.get('description','N/A')}", ""]

            if verdict["risk_factors"]:
                lines.append("  [!] RISK FACTORS IDENTIFIED:")
                for factor in verdict["risk_factors"]:
                    lines.append(f"      • {factor}")
                lines.append("")
            else:
                lines += ["  [✓] No risk factors detected.", ""]

            for ip, ip_data in ea["enrichment"]["ips"].items():
                lines.append(f"  ┌─ IP ENRICHMENT : {ip}  [{ip_data.get('field','')}]")
                vt = ip_data.get("virustotal", {})
                if vt.get("status") == "found":
                    lines += [
                        "  │  VirusTotal:",
                        f"  │    Malicious / Suspicious  : {vt.get('malicious_votes',0)} / {vt.get('suspicious_votes',0)}",
                        f"  │    Harmless / Undetected   : {vt.get('harmless_votes',0)} / {vt.get('undetected_votes',0)}",
                        f"  │    Country / ASN            : {vt.get('country','?')} / AS{vt.get('asn','?')} ({vt.get('as_owner','?')})",
                        f"  │    VT Reputation Score      : {vt.get('reputation','N/A')}",
                        f"  │    Tags                     : {', '.join(vt.get('tags',[])) or 'none'}",
                    ]
                else:
                    lines.append(f"  │  VirusTotal  : {vt.get('status','error').upper()}")
                abuse = ip_data.get("abuseipdb", {})
                if abuse.get("status") == "found":
                    lines += [
                        "  │",
                        "  │  AbuseIPDB:",
                        f"  │    Abuse Confidence Score   : {abuse.get('abuse_confidence_score',0)}%",
                        f"  │    Total Reports             : {abuse.get('total_reports',0)} by {abuse.get('distinct_users',0)} distinct user(s)",
                        f"  │    Country / ISP             : {abuse.get('country_code','?')} / {abuse.get('isp','?')}",
                        f"  │    Usage Type               : {abuse.get('usage_type','?')}",
                        f"  │    Is Whitelisted            : {abuse.get('is_whitelisted',False)}",
                        f"  │    Last Reported             : {abuse.get('last_reported_at') or 'Never'}",
                    ]
                else:
                    lines.append(f"  │  AbuseIPDB   : {abuse.get('status','error').upper()}")
                lines += ["  └" + "─" * (W - 3), ""]

            for domain, dom_data in ea["enrichment"]["domains"].items():
                lines.append(f"  ┌─ DOMAIN ENRICHMENT : {domain}")
                vt = dom_data.get("virustotal", {})
                if vt.get("status") == "found":
                    cats = ", ".join(vt.get("categories", {}).values()) or "none"
                    lines += [
                        "  │  VirusTotal:",
                        f"  │    Malicious / Suspicious  : {vt.get('malicious_votes',0)} / {vt.get('suspicious_votes',0)}",
                        f"  │    Harmless / Undetected   : {vt.get('harmless_votes',0)} / {vt.get('undetected_votes',0)}",
                        f"  │    Registrar               : {vt.get('registrar','?')}",
                        f"  │    VT Reputation Score      : {vt.get('reputation','N/A')}",
                        f"  │    Categories              : {cats}",
                        f"  │    Tags                    : {', '.join(vt.get('tags',[])) or 'none'}",
                    ]
                else:
                    lines.append(f"  │  VirusTotal  : {vt.get('status','error').upper()}")
                lines += ["  └" + "─" * (W - 3), ""]

            for file_hash, hash_data in ea["enrichment"]["hashes"].items():
                lines.append(f"  ┌─ FILE HASH ENRICHMENT : {file_hash}")
                vt = hash_data.get("virustotal", {})
                if vt.get("status") == "found":
                    lines += [
                        "  │  VirusTotal:",
                        f"  │    Malicious / Suspicious  : {vt.get('malicious_votes',0)} / {vt.get('suspicious_votes',0)}",
                        f"  │    Harmless / Undetected   : {vt.get('harmless_votes',0)} / {vt.get('undetected_votes',0)}",
                        f"  │    File Type               : {vt.get('file_type','?')}",
                        f"  │    Meaningful Name         : {vt.get('meaningful_name','?')}",
                        f"  │    File Size               : {vt.get('file_size_bytes',0):,} bytes",
                        f"  │    Times Submitted         : {vt.get('times_submitted',0):,}",
                        f"  │    SHA-256                 : {vt.get('sha256','?')}",
                        f"  │    Tags                    : {', '.join(vt.get('tags',[])) or 'none'}",
                    ]
                else:
                    lines.append(f"  │  VirusTotal  : {vt.get('status','error').upper()}")
                lines += ["  └" + "─" * (W - 3), ""]

        lines += ["=" * W, "  END OF REPORT", "=" * W]
        return "\n".join(lines) + "\n"

    # -------------------------------------------------------------------------
    # HTML report
    # -------------------------------------------------------------------------

    # Colour palette per verdict / severity
    _VERDICT_COLOR = {
        "MALICIOUS":              ("#f85149", "#3d0c0a"),
        "SUSPICIOUS":             ("#d29922", "#3d2c00"),
        "POTENTIALLY_SUSPICIOUS": ("#388bfd", "#0d2044"),
        "CLEAN":                  ("#3fb950", "#0d2b0e"),
    }
    _SEV_COLOR = {
        "CRITICAL": "#f85149",
        "HIGH":     "#d29922",
        "MEDIUM":   "#388bfd",
        "LOW":      "#3fb950",
    }

    def _verdict_badge(self, verdict: str) -> str:
        fg, bg = self._VERDICT_COLOR.get(verdict, ("#8b949e", "#1c2128"))
        return (f'<span class="badge" style="background:{bg};color:{fg};'
                f'border:1px solid {fg}">{esc(verdict)}</span>')

    def _sev_badge(self, sev: str) -> str:
        color = self._SEV_COLOR.get(sev, "#8b949e")
        return (f'<span class="badge" style="background:{color}22;color:{color};'
                f'border:1px solid {color}">{esc(sev)}</span>')

    def _score_bar(self, score: int, verdict: str) -> str:
        fg, _ = self._VERDICT_COLOR.get(verdict, ("#8b949e", "#1c2128"))
        return (f'<div class="score-bar-wrap">'
                f'<div class="score-bar" style="width:{score}%;background:{fg}"></div>'
                f'</div>'
                f'<span class="score-label" style="color:{fg}">{score}/100</span>')

    def _ioc_table(self, rows: List[Tuple[str, str]]) -> str:
        """Render a list of (label, value) pairs as an HTML table."""
        html = '<table class="ioc-table">'
        for label, value in rows:
            html += f'<tr><th>{esc(label)}</th><td>{esc(value)}</td></tr>'
        html += "</table>"
        return html

    def _build_html_report(self, enriched_alerts: list) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        sev_counts: Dict[str, int] = {}
        for ea in enriched_alerts:
            s = ea["alert"].get("severity", "UNKNOWN")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        total_ips     = sum(len(ea["enrichment"]["ips"])     for ea in enriched_alerts)
        total_domains = sum(len(ea["enrichment"]["domains"]) for ea in enriched_alerts)
        total_hashes  = sum(len(ea["enrichment"]["hashes"])  for ea in enriched_alerts)

        malicious_count = sum(
            1 for ea in enriched_alerts if ea["verdict"]["verdict"] == "MALICIOUS"
        )

        # ── CSS ──────────────────────────────────────────────────────────────
        css = """
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
            background: #0d1117; color: #c9d1d9; min-height: 100vh;
        }
        a { color: #58a6ff; }
        header {
            background: #161b22; border-bottom: 1px solid #30363d;
            padding: 20px 32px; display: flex; align-items: center; gap: 16px;
        }
        header .logo {
            width: 40px; height: 40px; background: #f85149;
            border-radius: 8px; display: flex; align-items: center;
            justify-content: center; font-size: 20px; flex-shrink: 0;
        }
        header h1 { font-size: 1.25rem; color: #f0f6fc; }
        header p  { font-size: 0.8rem; color: #8b949e; margin-top: 2px; }
        main { max-width: 1100px; margin: 0 auto; padding: 32px 24px; }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 16px; margin-bottom: 32px;
        }
        .stat-card {
            background: #161b22; border: 1px solid #30363d;
            border-radius: 10px; padding: 20px 16px; text-align: center;
        }
        .stat-card .num  { font-size: 2rem; font-weight: 700; color: #f0f6fc; }
        .stat-card .num.red    { color: #f85149; }
        .stat-card .num.orange { color: #d29922; }
        .stat-card .num.blue   { color: #388bfd; }
        .stat-card .num.green  { color: #3fb950; }
        .stat-card .lbl { font-size: 0.75rem; color: #8b949e; margin-top: 4px; }

        h2.section-title {
            font-size: 1rem; color: #8b949e; text-transform: uppercase;
            letter-spacing: .08em; margin-bottom: 16px;
            border-bottom: 1px solid #30363d; padding-bottom: 8px;
        }

        .alert-card {
            background: #161b22; border: 1px solid #30363d;
            border-radius: 10px; margin-bottom: 24px; overflow: hidden;
        }
        .alert-header {
            padding: 16px 20px; border-bottom: 1px solid #30363d;
            display: flex; flex-wrap: wrap; align-items: center; gap: 10px;
        }
        .alert-header .alert-id { font-weight: 700; color: #f0f6fc; font-size: 1rem; }
        .alert-header .spacer   { flex: 1; }
        .alert-meta { padding: 16px 20px; display: grid; grid-template-columns: 1fr 1fr; gap: 6px 24px; }
        .alert-meta .field      { font-size: 0.82rem; color: #8b949e; }
        .alert-meta .value      { font-size: 0.82rem; color: #c9d1d9; font-family: monospace; }

        .risk-row { padding: 12px 20px; border-top: 1px solid #30363d; display: flex; align-items: center; gap: 16px; }
        .score-bar-wrap { flex: 1; height: 8px; background: #21262d; border-radius: 4px; overflow: hidden; }
        .score-bar      { height: 100%; border-radius: 4px; transition: width .4s; }
        .score-label    { font-size: 0.9rem; font-weight: 700; min-width: 60px; text-align: right; }

        .risk-factors { padding: 12px 20px; border-top: 1px solid #30363d; background: #0d1117; }
        .risk-factors h4 { font-size: 0.78rem; text-transform: uppercase; color: #f85149; letter-spacing: .06em; margin-bottom: 8px; }
        .risk-factors ul { list-style: none; }
        .risk-factors ul li { font-size: 0.82rem; padding: 3px 0; color: #f0a15a; }
        .risk-factors ul li::before { content: "⚠ "; }

        .clean-note { padding: 12px 20px; border-top: 1px solid #30363d; font-size: 0.82rem; color: #3fb950; }
        .clean-note::before { content: "✓  "; }

        .ioc-sections { padding: 0 20px 16px; }
        .ioc-block {
            background: #0d1117; border: 1px solid #30363d;
            border-radius: 8px; margin-top: 12px; overflow: hidden;
        }
        .ioc-block summary {
            padding: 10px 14px; cursor: pointer; font-size: 0.83rem;
            font-weight: 600; color: #58a6ff; list-style: none;
            display: flex; align-items: center; gap: 8px;
            user-select: none;
        }
        .ioc-block summary::-webkit-details-marker { display: none; }
        .ioc-block summary::before { content: "▶"; font-size: 0.65rem; }
        details[open] summary::before { content: "▼"; }
        .ioc-block summary:hover { background: #161b22; }
        .ioc-inner { padding: 0 14px 12px; }

        .provider-label {
            font-size: 0.7rem; text-transform: uppercase; letter-spacing: .08em;
            color: #8b949e; margin: 10px 0 6px; border-bottom: 1px solid #21262d;
            padding-bottom: 4px;
        }
        .ioc-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
        .ioc-table th {
            text-align: left; color: #8b949e; font-weight: 400;
            padding: 3px 12px 3px 0; width: 200px; white-space: nowrap;
        }
        .ioc-table td { color: #c9d1d9; font-family: monospace; padding: 3px 0; word-break: break-all; }
        .ioc-table td.val-malicious { color: #f85149; font-weight: 700; }
        .ioc-table td.val-clean     { color: #3fb950; }

        .badge {
            display: inline-block; padding: 2px 10px; border-radius: 20px;
            font-size: 0.75rem; font-weight: 700; letter-spacing: .04em;
        }
        .status-pill {
            display: inline-block; padding: 1px 8px; border-radius: 4px;
            font-size: 0.72rem; background: #21262d; color: #8b949e;
        }
        footer {
            text-align: center; color: #30363d; font-size: 0.72rem;
            padding: 32px; border-top: 1px solid #21262d; margin-top: 40px;
        }
        @media (max-width: 600px) {
            .alert-meta { grid-template-columns: 1fr; }
            header { padding: 16px; }
            main   { padding: 16px; }
        }
        """

        # ── Helper: render one IP block ──────────────────────────────────────
        def render_ip_block(ip: str, ip_data: Dict) -> str:
            vt    = ip_data.get("virustotal", {})
            abuse = ip_data.get("abuseipdb",  {})
            field = ip_data.get("field", "")

            vt_rows: List[Tuple[str, str]] = []
            if vt.get("status") == "found":
                mal = vt.get("malicious_votes", 0)
                sus = vt.get("suspicious_votes", 0)
                vt_rows = [
                    ("Malicious detections",  str(mal)),
                    ("Suspicious detections", str(sus)),
                    ("Harmless / Undetected",
                     f"{vt.get('harmless_votes',0)} / {vt.get('undetected_votes',0)}"),
                    ("Country",  vt.get("country",  "Unknown")),
                    ("ASN",      f"AS{vt.get('asn','?')} — {vt.get('as_owner','?')}"),
                    ("Reputation score",  str(vt.get("reputation", 0))),
                    ("Tags",     ", ".join(vt.get("tags", [])) or "none"),
                ]
            else:
                vt_rows = [("Status", vt.get("status", "error").upper())]

            abuse_rows: List[Tuple[str, str]] = []
            if abuse.get("status") == "found":
                conf = abuse.get("abuse_confidence_score", 0)
                abuse_rows = [
                    ("Abuse confidence",  f"{conf}%"),
                    ("Total reports",
                     f"{abuse.get('total_reports',0):,} by {abuse.get('distinct_users',0):,} user(s)"),
                    ("Country / ISP",
                     f"{abuse.get('country_code','?')} / {abuse.get('isp','?')}"),
                    ("Usage type",      abuse.get("usage_type",   "Unknown")),
                    ("Whitelisted",     str(abuse.get("is_whitelisted", False))),
                    ("Last reported",   str(abuse.get("last_reported_at") or "Never")),
                ]
            else:
                abuse_rows = [("Status", abuse.get("status", "error").upper())]

            # colour-code the malicious count cell
            mal_val = vt.get("malicious_votes", 0) if vt.get("status") == "found" else 0
            mal_cls = "val-malicious" if mal_val > 0 else "val-clean"

            vt_html    = '<table class="ioc-table">'
            for label, value in vt_rows:
                cls = mal_cls if label == "Malicious detections" else ""
                vt_html += (f'<tr><th>{esc(label)}</th>'
                            f'<td class="{cls}">{esc(value)}</td></tr>')
            vt_html += "</table>"

            return f"""
            <details class="ioc-block">
              <summary>IP Address — {esc(ip)}
                <span class="status-pill">{esc(field)}</span>
              </summary>
              <div class="ioc-inner">
                <div class="provider-label">VirusTotal</div>
                {vt_html}
                <div class="provider-label" style="margin-top:12px">AbuseIPDB</div>
                {self._ioc_table(abuse_rows)}
              </div>
            </details>"""

        def render_domain_block(domain: str, dom_data: Dict) -> str:
            vt = dom_data.get("virustotal", {})
            if vt.get("status") == "found":
                cats = ", ".join(vt.get("categories", {}).values()) or "none"
                mal  = vt.get("malicious_votes", 0)
                rows = [
                    ("Malicious detections",  str(mal)),
                    ("Suspicious detections", str(vt.get("suspicious_votes", 0))),
                    ("Harmless / Undetected",
                     f"{vt.get('harmless_votes',0)} / {vt.get('undetected_votes',0)}"),
                    ("Registrar",        vt.get("registrar",  "Unknown")),
                    ("Reputation score", str(vt.get("reputation", 0))),
                    ("Categories",       cats),
                    ("Tags",             ", ".join(vt.get("tags", [])) or "none"),
                ]
                mal_cls = "val-malicious" if mal > 0 else "val-clean"
                table   = '<table class="ioc-table">'
                for label, value in rows:
                    cls = mal_cls if label == "Malicious detections" else ""
                    table += (f'<tr><th>{esc(label)}</th>'
                              f'<td class="{cls}">{esc(value)}</td></tr>')
                table += "</table>"
            else:
                table = self._ioc_table([("Status", vt.get("status", "error").upper())])

            return f"""
            <details class="ioc-block">
              <summary>Domain — {esc(domain)}</summary>
              <div class="ioc-inner">
                <div class="provider-label">VirusTotal</div>
                {table}
              </div>
            </details>"""

        def render_hash_block(file_hash: str, hash_data: Dict) -> str:
            vt = hash_data.get("virustotal", {})
            if vt.get("status") == "found":
                mal  = vt.get("malicious_votes", 0)
                rows = [
                    ("Malicious detections",  str(mal)),
                    ("Suspicious detections", str(vt.get("suspicious_votes", 0))),
                    ("Harmless / Undetected",
                     f"{vt.get('harmless_votes',0)} / {vt.get('undetected_votes',0)}"),
                    ("File type",       vt.get("file_type",       "Unknown")),
                    ("Meaningful name", vt.get("meaningful_name", "Unknown")),
                    ("File size",       f"{vt.get('file_size_bytes',0):,} bytes"),
                    ("Times submitted", f"{vt.get('times_submitted',0):,}"),
                    ("MD5",             vt.get("md5",  "")),
                    ("SHA-256",         vt.get("sha256","Unknown")),
                    ("Tags",            ", ".join(vt.get("tags", [])) or "none"),
                ]
                mal_cls = "val-malicious" if mal > 0 else "val-clean"
                table   = '<table class="ioc-table">'
                for label, value in rows:
                    cls = mal_cls if label == "Malicious detections" else ""
                    table += (f'<tr><th>{esc(label)}</th>'
                              f'<td class="{cls}">{esc(value)}</td></tr>')
                table += "</table>"
            else:
                table = self._ioc_table([("Status", vt.get("status", "error").upper())])

            return f"""
            <details class="ioc-block">
              <summary>File Hash (MD5) — {esc(file_hash)}</summary>
              <div class="ioc-inner">
                <div class="provider-label">VirusTotal</div>
                {table}
              </div>
            </details>"""

        # ── Alert cards ──────────────────────────────────────────────────────
        alert_cards_html = ""
        for i, ea in enumerate(enriched_alerts, 1):
            alert   = ea["alert"]
            verdict = ea["verdict"]
            v_str   = verdict["verdict"]
            score   = verdict["risk_score"]

            meta_fields = [
                ("Alert Type",  alert.get("alert_type",  "N/A")),
                ("Timestamp",   alert.get("timestamp",   "N/A")),
                ("Source Host", alert.get("source_host", "N/A")),
                ("Source IP",   alert.get("source_ip",   "N/A")),
                ("Destination IP",     alert.get("destination_ip",     "N/A")),
                ("Destination Domain", alert.get("destination_domain") or "—"),
                ("File Name",   alert.get("file_name")   or "—"),
                ("File Hash MD5", alert.get("file_hash_md5") or "—"),
                ("Process",     alert.get("process")     or "—"),
                ("SIEM Rule",   alert.get("rule_triggered") or "—"),
            ]
            meta_html = "".join(
                f'<div class="field">{esc(k)}</div><div class="value">{esc(v)}</div>'
                for k, v in meta_fields
            )

            risk_factors_html = ""
            if verdict["risk_factors"]:
                items = "".join(f"<li>{esc(f)}</li>" for f in verdict["risk_factors"])
                risk_factors_html = f"""
                <div class="risk-factors">
                  <h4>Risk Factors Identified</h4>
                  <ul>{items}</ul>
                </div>"""
            else:
                risk_factors_html = '<div class="clean-note">No risk factors detected</div>'

            ioc_html = ""
            for ip, ip_data in ea["enrichment"]["ips"].items():
                ioc_html += render_ip_block(ip, ip_data)
            for domain, dom_data in ea["enrichment"]["domains"].items():
                ioc_html += render_domain_block(domain, dom_data)
            for file_hash, hash_data in ea["enrichment"]["hashes"].items():
                ioc_html += render_hash_block(file_hash, hash_data)

            desc = esc(alert.get("description", ""))

            alert_cards_html += f"""
            <div class="alert-card">
              <div class="alert-header">
                <span class="alert-id">Alert #{i}: {esc(alert.get('alert_id','N/A'))}</span>
                {self._sev_badge(alert.get('severity','?'))}
                {self._verdict_badge(v_str)}
                <span class="spacer"></span>
              </div>
              <div class="alert-meta">{meta_html}</div>
              <div style="padding:8px 20px 12px;font-size:0.82rem;color:#8b949e;border-top:1px solid #30363d">
                {desc}
              </div>
              <div class="risk-row">
                <span style="font-size:0.78rem;color:#8b949e;min-width:80px">Risk Score</span>
                {self._score_bar(score, v_str)}
              </div>
              {risk_factors_html}
              {"<div class='ioc-sections'>" + ioc_html + "</div>" if ioc_html else ""}
            </div>"""

        # ── Summary cards ────────────────────────────────────────────────────
        def stat(num: int, label: str, color: str = "") -> str:
            cls = f' class="num {color}"' if color else ' class="num"'
            return (f'<div class="stat-card">'
                    f'<div{cls}>{num}</div>'
                    f'<div class="lbl">{label}</div></div>')

        summary_html = (
            stat(len(enriched_alerts), "Total Alerts")
            + stat(malicious_count, "Malicious", "red")
            + stat(sev_counts.get("CRITICAL", 0), "Critical", "red")
            + stat(sev_counts.get("HIGH", 0), "High", "orange")
            + stat(total_ips, "IPs Enriched", "blue")
            + stat(total_domains, "Domains Enriched", "blue")
            + stat(total_hashes, "Hashes Enriched", "blue")
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SOC Incident Enrichment Report — {esc(now)}</title>
  <style>{css}</style>
</head>
<body>
  <header>
    <div class="logo">🛡</div>
    <div>
      <h1>SOC Workflow Automation — Incident Enrichment Report</h1>
      <p>Generated: {esc(now)}</p>
    </div>
  </header>
  <main>
    <h2 class="section-title">Executive Summary</h2>
    <div class="summary-grid">{summary_html}</div>

    <h2 class="section-title">Alert Details</h2>
    {alert_cards_html}
  </main>
  <footer>
    SOC Workflow Automation &nbsp;|&nbsp;
    Enriched via VirusTotal API v3 &amp; AbuseIPDB API v2 &nbsp;|&nbsp;
    {esc(now)}
  </footer>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SOC Workflow Automation — Alert Enrichment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python src/soc_enrichment.py\n"
            "  python src/soc_enrichment.py data/sample_alerts.json\n"
            "  python src/soc_enrichment.py data/alerts.json --output-dir /tmp/reports\n"
        ),
    )
    parser.add_argument(
        "alerts_file", nargs="?", default="data/sample_alerts.json",
        help="Path to SIEM alert JSON file (default: data/sample_alerts.json)",
    )
    parser.add_argument(
        "--output-dir", default="reports",
        help="Directory to save reports (default: reports/)",
    )
    parser.add_argument(
        "--vt-key", default=VIRUSTOTAL_API_KEY,
        help="VirusTotal API key (overrides VIRUSTOTAL_API_KEY env var)",
    )
    parser.add_argument(
        "--abuse-key", default=ABUSEIPDB_API_KEY,
        help="AbuseIPDB API key (overrides ABUSEIPDB_API_KEY env var)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not args.vt_key:
        log.error("VirusTotal API key missing. Set VIRUSTOTAL_API_KEY in .env or use --vt-key")
        sys.exit(1)
    if not args.abuse_key:
        log.error("AbuseIPDB API key missing. Set ABUSEIPDB_API_KEY in .env or use --abuse-key")
        sys.exit(1)

    alerts_path = Path(args.alerts_file)
    if not alerts_path.exists():
        log.error(f"Alert file not found: {alerts_path.resolve()}")
        sys.exit(1)

    with open(alerts_path, encoding="utf-8") as f:
        try:
            alerts = json.load(f)
        except json.JSONDecodeError as exc:
            log.error(f"Invalid JSON in alert file: {exc}")
            sys.exit(1)

    if not isinstance(alerts, list) or len(alerts) == 0:
        log.error("Alert file must contain a non-empty JSON array.")
        sys.exit(1)

    log.info(f"Loaded {len(alerts)} alert(s) from {alerts_path}")
    log.info("Note: VirusTotal free tier = 4 req/min — expect ~16 s between lookups.")

    engine          = AlertEnrichmentEngine(args.vt_key, args.abuse_key)
    enriched_alerts = []

    for idx, alert in enumerate(alerts, 1):
        log.info(
            f"── Processing alert {idx}/{len(alerts)}: "
            f"{alert.get('alert_id','N/A')} [{alert.get('severity','?')}] ──"
        )
        enriched_alerts.append(engine.enrich_alert(alert))

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    reporter  = ReportGenerator(Path(args.output_dir))
    json_path, text_path, html_path = reporter.generate(enriched_alerts, timestamp)

    print()
    print("=" * 62)
    print("  ENRICHMENT COMPLETE")
    print("=" * 62)
    print(f"  Alerts processed : {len(enriched_alerts)}")
    print(f"  JSON report      : {json_path}")
    print(f"  Text report      : {text_path}")
    print(f"  HTML report      : {html_path}")
    print("=" * 62)
    print()
    print(f"  {'Alert ID':<20} {'Verdict':<26} Risk Score")
    print(f"  {'-'*18} {'-'*24} ----------")
    for ea in enriched_alerts:
        alert_id = ea["alert"].get("alert_id", "N/A")
        v        = ea["verdict"]
        print(f"  {alert_id:<20} {v['verdict']:<26} {v['risk_score']}/100")
    print()


if __name__ == "__main__":
    main()
