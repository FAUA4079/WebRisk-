#!/usr/bin/env python3
"""
webrisk.py - Web scan + rule matcher in LogRisk style (final)

Usage examples:
  sudo ./webrisk.py --target testphp.vulnweb.com --rules web_rules.json -O report.txt --json-report -v
  sudo ./webrisk.py --targets targets.txt --rules web_rules.json --skip-ping --run-nmap --run-whatweb --run-nikto

Notes:
- Only scan systems you own or have explicit permission to test.
- Rule file must be either a JSON object with "rules":[...] or a JSON array of rule objects.
- Rule object example keys: id, name, pattern, is_regex (true/false), weight, suggested_treatment, category
"""
import os
import sys
import argparse
import subprocess
import shutil
import json
import re
from datetime import datetime

# --------------- Helpers ---------------
def now_ts():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

def safe_mkdir(path):
    os.makedirs(path, exist_ok=True)

def ping_target(target, count=3, wait=2):
    """Return True if ICMP ping appears successful; False otherwise."""
    ping_bin = shutil.which("ping")
    if not ping_bin:
        print("[!] ping not found on system; ping check unavailable.")
        return False
    cmd = f"ping -c {count} -W {wait} {target}"
    try:
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=(count * (wait + 3)))
        out = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode == 0:
            return True
        if "0% packet loss" in out or "ttl=" in out.lower():
            return True
        return False
    except Exception as e:
        print("[!] ping error:", e)
        return False

def run_cmd_to_file(cmd, outpath, timeout=600):
    """Run a command, save stdout+stderr to outpath, return collected output text."""
    print(f"[+] RUN: {cmd}")
    try:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
        out = (out or "") + "\n[timeout]\n"
    except Exception as e:
        out = f"[error running command: {e}]"
    try:
        with open(outpath, "w", encoding="utf-8", errors="ignore") as f:
            f.write(f"$ {cmd}\n\n")
            f.write(out or "")
    except Exception as e:
        print("[!] Failed to write output file:", outpath, e)
    return out or ""

def load_rules(rules_file):
    """Load rules: supports { "rules":[...] } or a plain list."""
    with open(rules_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "rules" in data:
        return data["rules"]
    if isinstance(data, list):
        return data
    raise ValueError("Invalid rules file format: must be list or {\"rules\":[...]}")

def predict_risk_level(weight):
    try:
        w = float(weight)
    except Exception:
        w = 0.0
    if w >= 7:
        return "High"
    elif w >= 4:
        return "Medium"
    else:
        return "Low"

def find_evidence_in_file(file_path, pattern, is_regex=True, context_lines=2, max_matches=8):
    """Return list of evidence dicts {file, line_no, snippet}."""
    evidence = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return evidence

    rx = None
    if is_regex:
        try:
            rx = re.compile(pattern, re.I)
        except re.error:
            rx = None  # fallback to substring

    for idx, line in enumerate(lines):
        matched = False
        if rx:
            if rx.search(line):
                matched = True
        else:
            if pattern.lower() in line.lower():
                matched = True

        if matched:
            start = max(0, idx - context_lines)
            end = min(len(lines), idx + context_lines + 1)
            snippet = "".join(lines[start:end]).strip()
            evidence.append({
                "file": os.path.basename(file_path),
                "line_no": idx + 1,
                "snippet": snippet
            })
            if len(evidence) >= max_matches:
                break
    return evidence

# --------------- Scanners ---------------
def scanner_nmap(target, raw_dir):
    out = os.path.join(raw_dir, "nmap.txt")
    cmd = f"nmap -Pn -sV {target}"
    txt = run_cmd_to_file(cmd, out, timeout=600)
    return txt, out

def scanner_whatweb(target, raw_dir):
    out = os.path.join(raw_dir, "whatweb.txt")
    if not shutil.which("whatweb"):
        with open(out, "w", encoding="utf-8") as f:
            f.write("whatweb not installed\n")
        return "whatweb not installed\n", out
    cmd = f"whatweb --no-errors {target}"
    txt = run_cmd_to_file(cmd, out, timeout=300)
    return txt, out

def scanner_nikto(target, raw_dir):
    out = os.path.join(raw_dir, "nikto.txt")
    if not shutil.which("nikto"):
        with open(out, "w", encoding="utf-8") as f:
            f.write("nikto not installed\n")
        return "nikto not installed\n", out
    cmd = f"nikto -h {target}"
    txt = run_cmd_to_file(cmd, out, timeout=900)
    return txt, out

# --------------- Reporting & saving ---------------
def create_results_folder(scan_type):
    base_folder = os.path.join("Results_output", scan_type)
    safe_mkdir(base_folder)
    timestamp = now_ts()
    run_folder = os.path.join(base_folder, timestamp)
    safe_mkdir(run_folder)
    return run_folder

def save_reports(matches, output_name, run_folder, raw_files, json_report=False):
    # Text report
    txt_path = os.path.join(run_folder, output_name)
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(f"WebRisk Report generated: {now_ts()}\n\n")
        for m in matches:
            f.write(f"ID: {m['id']} | Risk: {m['name']} | Weight: {m['weight']} | Level: {m['level']}\n")
            if m.get("category"):
                f.write(f"Category: {m['category']}\n")
            if m.get("suggested_treatment"):
                f.write(f"Fix: {m['suggested_treatment']}\n")
            f.write("Evidence:\n")
            for ev in m.get("evidence", []):
                f.write(f" - {ev['file']}:{ev['line_no']}: {ev['snippet']}\n")
            f.write("-" * 60 + "\n")
    print(f"[+] Saved text report: {txt_path}")

    # JSON report
    if json_report:
        jpath = os.path.join(run_folder, "report.json")
        with open(jpath, "w", encoding="utf-8") as f:
            json.dump(matches, f, indent=2)
        print(f"[+] Saved JSON report: {jpath}")

    # Copy raw files into raw/ folder
    raw_out_dir = os.path.join(run_folder, "raw")
    safe_mkdir(raw_out_dir)
    for rf in raw_files:
        # If rf is a tuple (maybe earlier code), support path extraction
        rf_path = rf if isinstance(rf, str) else (rf[1] if isinstance(rf, (list, tuple)) and len(rf) > 1 else None)
        if not rf_path:
            continue
        try:
            shutil.copy(rf_path, os.path.join(raw_out_dir, os.path.basename(rf_path)))
        except Exception:
            # fallback: read & write
            try:
                with open(rf_path, "r", encoding="utf-8", errors="ignore") as src:
                    txt = src.read()
                with open(os.path.join(raw_out_dir, os.path.basename(rf_path)), "w", encoding="utf-8") as dst:
                    dst.write(txt)
            except Exception:
                pass

    # Per-risk evidence folders
    for m in matches:
        safe_name = re.sub(r'[^A-Za-z0-9_\-]', '_', f"{m['id']}_{m['name']}")
        risk_folder = os.path.join(run_folder, safe_name)
        safe_mkdir(risk_folder)
        with open(os.path.join(risk_folder, "evidence.txt"), "a", encoding="utf-8") as f:
            for ev in m.get("evidence", []):
                f.write(f"{ev['file']}:{ev['line_no']}: {ev['snippet']}\n")
    print(f"[+] All outputs saved in: {run_folder}")

# --------------- Core flow ---------------
def process_target(target, rules, args):
    run_folder = create_results_folder("WebScan")

    # Ping pre-check
    if not args.skip_ping:
        print(f"[+] Pinging {target} ...")
        ok = ping_target(target)
        if not ok:
            print(f"[!] Ping to {target} failed or ICMP blocked. Skipping scans for this target.")
            with open(os.path.join(run_folder, "README.txt"), "w", encoding="utf-8") as f:
                f.write(f"Target: {target}\nTimestamp: {now_ts()}\nPingCheck: FAILED\nNote: Use --skip-ping to force scans.\n")
            return
        else:
            print("[+] Ping OK — proceeding with scans.")
    else:
        print("[!] --skip-ping used; bypassing ping pre-check.")

    # Ensure raw folder exists in run_folder
    raw_dir = os.path.join(run_folder, "raw")
    safe_mkdir(raw_dir)

    # Run selected scanners (or default to all)
    raw_files = []
    ran_any = False

    if args.run_nmap:
        ran_any = True
        print("[*] Running nmap ...")
        _, nmap_path = scanner_nmap(target, raw_dir)
        raw_files.append(nmap_path)

    if args.run_whatweb:
        ran_any = True
        print("[*] Running whatweb ...")
        _, what_path = scanner_whatweb(target, raw_dir)
        raw_files.append(what_path)

    if args.run_nikto:
        ran_any = True
        print("[*] Running nikto ...")
        _, nikto_path = scanner_nikto(target, raw_dir)
        raw_files.append(nikto_path)

    if not ran_any:
        # run all by default
        print("[*] No scanner flag provided — running nmap, whatweb, nikto by default.")
        _, nmap_path = scanner_nmap(target, raw_dir); raw_files.append(nmap_path)
        _, what_path = scanner_whatweb(target, raw_dir); raw_files.append(what_path)
        _, nikto_path = scanner_nikto(target, raw_dir); raw_files.append(nikto_path)

    # Rule matching
    matches = []
    for rule in rules:
        pattern = rule.get("pattern", "")
        is_regex = rule.get("is_regex", True)
        evidence_total = []
        for rf in raw_files:
            evidence_total.extend(find_evidence_in_file(rf, pattern, is_regex, context_lines=2, max_matches=6))
            if len(evidence_total) >= 6:
                break
        if evidence_total:
            m = {
                "id": rule.get("id", rule.get("name", "unknown")),
                "name": rule.get("name", rule.get("id", "unknown")),
                "pattern": pattern,
                "weight": rule.get("weight", 5),
                "level": predict_risk_level(rule.get("weight", 5)),
                "category": rule.get("category", ""),
                "suggested_treatment": rule.get("suggested_treatment", ""),
                "evidence": evidence_total
            }
            matches.append(m)
            if args.verbose:
                print(f"[{m['level']}] Matched rule {m['id']} - {m['name']} ({len(evidence_total)} evidence items)")

    # Save reports
    save_reports(matches, args.output, run_folder, raw_files, json_report=args.json_report)

# --------------- CLI ---------------
def print_help_and_exit():
    print("""
WebRisk Commands Guide:

Basic usage:
  webrisk.py --target <domain_or_ip> --rules <rules.json> [options]

Scan modes:
  --target <domain_or_ip>         Single target to scan
  --targets <file>                File with newline-separated targets

Scanners (optional):
  --run-nmap      Run nmap
  --run-whatweb   Run whatweb
  --run-nikto     Run nikto

Other options:
  --rules <file>   Rules JSON file (required)
  -O --output name  Text report filename (default: web_report.txt)
  --json-report     Save JSON report
  -v --verbose      Verbose output
  --skip-ping       Skip ping pre-check
  -h --help         Show help

Examples:
  sudo ./webrisk.py --target testphp.vulnweb.com --rules web_rules.json -O report.txt --json-report -v
  sudo ./webrisk.py --targets targets.txt --rules web_rules.json --skip-ping
""")
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--target", help="Single target (ip/domain)")
    parser.add_argument("--targets", help="File with targets (one per line)")
    parser.add_argument("--rules", required=False, help="Rules JSON file (array or {\"rules\":[...]})")
    parser.add_argument("-O", "--output", default="web_report.txt", help="Output text report name")
    parser.add_argument("--json-report", action="store_true", help="Save JSON report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    parser.add_argument("--run-nmap", action="store_true", help="Run nmap")
    parser.add_argument("--run-whatweb", action="store_true", help="Run whatweb")
    parser.add_argument("--run-nikto", action="store_true", help="Run nikto")
    parser.add_argument("--skip-ping", action="store_true", help="Skip ping pre-check")
    parser.add_argument("-h", "--help", action="store_true", help="Show help")
    args = parser.parse_args()

    if args.help or (not args.target and not args.targets):
        print_help_and_exit()

    if not args.rules:
        print("[!] Please specify a rules file with --rules (JSON).")
        sys.exit(1)
    if not os.path.exists(args.rules):
        print(f"[!] Rules file not found: {args.rules}")
        sys.exit(1)

    try:
        rules = load_rules(args.rules)
    except Exception as e:
        print("[!] Failed to load rules file:", e)
        sys.exit(1)

    targets = []
    if args.target:
        targets = [args.target.strip()]
    else:
        if not os.path.exists(args.targets):
            print(f"[!] Targets file not found: {args.targets}")
            sys.exit(1)
        with open(args.targets, "r", encoding="utf-8") as f:
            targets = [ln.strip() for ln in f if ln.strip()]

    # Legal reminder
    print("⚠️  Legal reminder: Only scan systems you own or have explicit permission to test.")

    for t in targets:
        print(f"\n=== Processing target: {t} ===")
        process_target(t, rules, args)

if __name__ == "__main__":
    main()
