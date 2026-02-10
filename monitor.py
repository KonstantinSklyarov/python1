 from __future__ import annotations

import os
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import requests
import pandas as pd
import matplotlib.pyplot as plt

SURICATA_LOG_PATH = os.getenv("SURICATA_LOG_PATH", "./logs/eve.json")
VULNERS_API_KEY = os.getenv("VULNERS_API_KEY", "")  
VULNERS_QUERY = os.getenv("VULNERS_QUERY", "OpenSSL")

CVSS_THRESHOLD = float(os.getenv("CVSS_THRESHOLD", "7.0"))
ALERT_COUNT_THRESHOLD = int(os.getenv("ALERT_COUNT_THRESHOLD", "3"))
TOP_N_IP = int(os.getenv("TOP_N_IP", "5"))

OUT_DIR = os.getenv("OUT_DIR", "./out")
REPORT_CSV = os.path.join(OUT_DIR, "report.csv")
REPORT_JSON = os.path.join(OUT_DIR, "report.json")
CHART_PNG = os.path.join(OUT_DIR, "chart.png")
BLOCKED_IPS_TXT = os.path.join(OUT_DIR, "blocked_ips.txt")

def ensure_out_dir() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)


def safe_float(x: Any) -> Optional[float]:
    try:
        if x is None:
            return None
        return float(x)
    except Exception:
        return None

def iter_suricata_events_from_file(filepath: str):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def load_suricata_events(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        return demo_suricata_events()
    events: List[Dict[str, Any]] = []
    if os.path.isdir(path):
        for name in os.listdir(path):
            if not (name.endswith(".json") or name.endswith(".log") or name.endswith(".txt")):
                continue
            fp = os.path.join(path, name)
            events.extend(list(iter_suricata_events_from_file(fp)))
    else:
        events.extend(list(iter_suricata_events_from_file(path)))

    return events if events else demo_suricata_events()

def demo_suricata_events() -> List[Dict[str, Any]]:
    now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    return [
        {
            "timestamp": now,
            "event_type": "alert",
            "src_ip": "10.0.0.5",
            "dest_ip": "1.1.1.1",
            "proto": "TCP",
            "alert": {"signature": "ET TROJAN Possible C2 Traffic", "severity": 1, "category": "A Network Trojan"},
        },
        {
            "timestamp": now,
            "event_type": "alert",
            "src_ip": "10.0.0.5",
            "dest_ip": "8.8.8.8",
            "proto": "UDP",
            "alert": {"signature": "ET DNS Possible DGA Domain", "severity": 2, "category": "Potentially Bad Traffic"},
        },
        {
            "timestamp": now,
            "event_type": "dns",
            "src_ip": "10.0.0.5",
            "dest_ip": "8.8.8.8",
            "dns": {"rrname": "suspicious-example.xyz", "rrtype": "A"},
        },
        {
            "timestamp": now,
            "event_type": "alert",
            "src_ip": "10.0.0.9",
            "dest_ip": "93.184.216.34",
            "proto": "TCP",
            "alert": {"signature": "ET SCAN Nmap Scripting Engine", "severity": 2, "category": "Attempted Information Leak"},
        },
        {
            "timestamp": now,
            "event_type": "alert",
            "src_ip": "10.0.0.9",
            "dest_ip": "93.184.216.34",
            "proto": "TCP",
            "alert": {"signature": "ET SCAN Nmap Scripting Engine", "severity": 2, "category": "Attempted Information Leak"},
        },
        {
            "timestamp": now,
            "event_type": "alert",
            "src_ip": "10.0.0.9",
            "dest_ip": "93.184.216.34",
            "proto": "TCP",
            "alert": {"signature": "ET SCAN Nmap Scripting Engine", "severity": 2, "category": "Attempted Information Leak"},
        },
    ]


def suricata_to_frames(events: List[Dict[str, Any]]) -> Tuple[pd.DataFrame, pd.DataFrame]:
    alerts_rows = []
    dns_rows = []

    for e in events:
        et = e.get("event_type")
        if et == "alert":
            al = e.get("alert", {}) or {}
            alerts_rows.append({
                "timestamp": e.get("timestamp"),
                "src_ip": e.get("src_ip"),
                "dest_ip": e.get("dest_ip"),
                "proto": e.get("proto"),
                "signature": al.get("signature"),
                "severity": al.get("severity"),
                "category": al.get("category"),
            })
        elif et == "dns":
            dns = e.get("dns", {}) or {}
            dns_rows.append({
                "timestamp": e.get("timestamp"),
                "src_ip": e.get("src_ip"),
                "dest_ip": e.get("dest_ip"),
                "rrname": dns.get("rrname"),
                "rrtype": dns.get("rrtype"),
            })
    alerts_df = pd.DataFrame(alerts_rows)
    dns_df = pd.DataFrame(dns_rows)
    return alerts_df, dns_df



# Vulners API

def vulners_search(query: str, api_key: str) -> pd.DataFrame:
    """
    Ищем уязвимости по ключевому слову/продукту.
    Если API key не задан — вернём демо-данные.
    """
    if not api_key:
        return demo_vulners(query)
    url = "https://vulners.com/api/v3/search/lucene/"
    payload = {"query": query, "size": 20, "apiKey": api_key}
    try:
        r = requests.post(url, json=payload, timeout=20)
        r.raise_for_status()
        data = r.json()
        items = (((data or {}).get("data") or {}).get("search") or [])
        rows = []
        for it in items:
            src = (it.get("_source") or {})
            cvss = None
            if isinstance(src.get("cvss"), dict):
                cvss = src["cvss"].get("score")
            cvss = safe_float(cvss)

            rows.append({
                "id": src.get("id") or it.get("_id"),
                "title": src.get("title"),
                "type": src.get("type"),
                "published": src.get("published"),
                "cvss": cvss,
                "href": src.get("href"),
            })

        df = pd.DataFrame(rows)
        if df.empty:
            return demo_vulners(query)
        return df

    except Exception:
        return demo_vulners(query)


def demo_vulners(query: str) -> pd.DataFrame:
    rows = [
        {"id": "CVE-2023-AAAA", "title": f"{query}: Remote Code Execution example", "type": "cve",
         "published": "2023-06-01", "cvss": 9.8, "href": "https://vulners.com/cve/CVE-2023-AAAA"},
        {"id": "CVE-2022-BBBB", "title": f"{query}: Privilege Escalation example", "type": "cve",
         "published": "2022-11-10", "cvss": 7.5, "href": "https://vulners.com/cve/CVE-2022-BBBB"},
        {"id": "CVE-2021-CCCC", "title": f"{query}: Information Disclosure example", "type": "cve",
         "published": "2021-03-15", "cvss": 5.3, "href": "https://vulners.com/cve/CVE-2021-CCCC"},
    ]
    return pd.DataFrame(rows)

@dataclass
class ThreatFinding:
    source: str
    kind: str
    severity: str
    details: Dict[str, Any]


def detect_threats(alerts_df: pd.DataFrame, dns_df: pd.DataFrame, vulns_df: pd.DataFrame) -> List[ThreatFinding]:
    findings: List[ThreatFinding] = []
    if not alerts_df.empty:
        for _, row in alerts_df.iterrows():
            sev = row.get("severity")
            sev_level = "low"
            if pd.notna(sev):
                try:
                    s = int(sev)
                    if s == 1:
                        sev_level = "high"
                    elif s == 2:
                        sev_level = "medium"
                except Exception:
                    pass

            if sev_level in ("high", "medium"):
                findings.append(ThreatFinding(
                    source="suricata",
                    kind="high_severity_alert",
                    severity=sev_level,
                    details={
                        "src_ip": row.get("src_ip"),
                        "dest_ip": row.get("dest_ip"),
                        "signature": row.get("signature"),
                        "category": row.get("category"),
                        "timestamp": row.get("timestamp"),
                    }
                ))

        ip_counts = alerts_df["src_ip"].value_counts(dropna=True)
        suspicious_ips = ip_counts[ip_counts >= ALERT_COUNT_THRESHOLD]
        for ip, cnt in suspicious_ips.items():
            findings.append(ThreatFinding(
                source="suricata",
                kind="suspicious_ip",
                severity="medium" if cnt < 10 else "high",
                details={"src_ip": ip, "alert_count": int(cnt), "threshold": ALERT_COUNT_THRESHOLD}
            ))

    if not vulns_df.empty and "cvss" in vulns_df.columns:
        for _, row in vulns_df.iterrows():
            cvss = row.get("cvss")
            if cvss is None or (isinstance(cvss, float) and pd.isna(cvss)):
                continue
            try:
                cv = float(cvss)
            except Exception:
                continue
            if cv >= CVSS_THRESHOLD:
                findings.append(ThreatFinding(
                    source="vulners",
                    kind="high_cvss_vuln",
                    severity="high" if cv >= 9 else "medium",
                    details={
                        "id": row.get("id"),
                        "title": row.get("title"),
                        "cvss": cv,
                        "published": row.get("published"),
                        "href": row.get("href"),
                        "threshold": CVSS_THRESHOLD,
                    }
                ))

    return findings


def react(findings: List[ThreatFinding]) -> List[str]:
    blocked: List[str] = []
    for f in findings:
        print(f"[!] Threat: source={f.source} kind={f.kind} severity={f.severity} details={f.details}")

        if f.kind == "suspicious_ip":
            ip = f.details.get("src_ip")
            if ip and ip not in blocked:
                blocked.append(ip)

    if blocked:
        ensure_out_dir()
        with open(BLOCKED_IPS_TXT, "w", encoding="utf-8") as w:
            for ip in blocked:
                w.write(ip + "\n")
        print(f"[+] Simulated blocklist saved to: {BLOCKED_IPS_TXT}")
    else:
        print("[+] No IPs to block (simulation).")

    return blocked

def findings_to_table(findings: List[ThreatFinding]) -> pd.DataFrame:
    rows = []
    for f in findings:
        flat = {
            "source": f.source,
            "kind": f.kind,
            "severity": f.severity,
        }
        for k, v in (f.details or {}).items():
            flat[f"details.{k}"] = v
        rows.append(flat)
    return pd.DataFrame(rows)


def save_report(df: pd.DataFrame) -> None:
    ensure_out_dir()
    df.to_csv(REPORT_CSV, index=False, encoding="utf-8")
    with open(REPORT_JSON, "w", encoding="utf-8") as f:
        json.dump(df.to_dict(orient="records"), f, ensure_ascii=False, indent=2)
    print(f"[+] Report saved: {REPORT_CSV}")
    print(f"[+] Report saved: {REPORT_JSON}")


def plot_top_ips(alerts_df: pd.DataFrame) -> None:
    ensure_out_dir()

    if alerts_df.empty or "src_ip" not in alerts_df.columns:
        plt.figure()
        plt.title("Top IPs (no data)")
        plt.savefig(CHART_PNG, dpi=150, bbox_inches="tight")
        plt.close()
        print(f"[+] Chart saved (empty): {CHART_PNG}")
        return

    counts = alerts_df["src_ip"].value_counts().head(TOP_N_IP)
    plt.figure()
    counts.plot(kind="bar")
    plt.title(f"Top-{TOP_N_IP} source IPs by Suricata alerts")
    plt.xlabel("Source IP")
    plt.ylabel("Alert count")
    plt.tight_layout()
    plt.savefig(CHART_PNG, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[+] Chart saved: {CHART_PNG}")

def main() -> int:
    print("[*] Loading Suricata events...")
    events = load_suricata_events(SURICATA_LOG_PATH)
    alerts_df, dns_df = suricata_to_frames(events)
    print(f"    Suricata: alerts={len(alerts_df)} dns={len(dns_df)}")

    print("[*] Fetching vulnerabilities from Vulners...")
    vulns_df = vulners_search(VULNERS_QUERY, VULNERS_API_KEY)
    print(f"    Vulners: items={len(vulns_df)} query={VULNERS_QUERY!r} (demo={not bool(VULNERS_API_KEY)})")

    print("[*] Detecting threats...")
    findings = detect_threats(alerts_df, dns_df, vulns_df)
    print(f"    Findings: {len(findings)}")

    print("[*] Reacting...")
    blocked = react(findings)

    print("[*] Building report...")
    report_df = findings_to_table(findings)
    summary_row = {
        "source": "summary",
        "kind": "summary",
        "severity": "",
        "details.blocked_ips_count": len(blocked),
        "details.total_findings": len(findings),
        "details.sources_used": "suricata+vulners",
    }
    report_df = pd.concat([report_df, pd.DataFrame([summary_row])], ignore_index=True)

    save_report(report_df)

    print("[*] Plotting chart...")
    plot_top_ips(alerts_df)

    print("[+] Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
