#!/usr/bin/env python3
"""
webrisk_no_nikto_smart.py — Improved WebRisk scanner (nikto removed)

This variant DOES NOT embed any rules. You must pass a rules JSON file with --rules.
Rules file format: either a JSON object with a "rules" array or a JSON array of rule objects.

- Cleaner rule parsing (supports substring/regex), safe regex compilation with fallback.
- CLI: list rules (reads from provided rules file), filter by tool, minimum score threshold, max evidence items.
- Scanners: nmap and whatweb (whatweb optional if not installed). No nikto.
- Outputs: plain text report, optional JSON report, raw outputs copied to results folder.

Usage examples:
  sudo ./webrisk_no_nikto_smart.py --target example.com --rules web_rules.json -O report.txt --json-report -v
  sudo ./webrisk_no_nikto_smart.py --targets targets.txt --rules web_rules.json --skip-ping --run-nmap --run-whatweb --min-score 5
  ./webrisk_no_nikto_smart.py --rules web_rules.json --list-rules

Notes:
- Only scan systems you own or have explicit permission to test.
"""

from __future__ import annotations

import os
import sys
import argparse
import subprocess
import shutil
import json
import re
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

# ----------------- Helpers -----------------

def now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def safe_mkdir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def ping_target(target: str, count: int = 3, wait: int = 2) -> bool:
    """Return True if ICMP ping appears successful; False otherwise."""
    ping_bin = which("ping")
    if not ping_bin:
        return False
    cmd = [ping_bin, "-c", str(count), "-W", str(wait), target]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=(count * (wait + 3)))
        out = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode == 0:
            return True
        if "0% packet loss" in out or "ttl=" in out.lower():
            return True
        return False
    except Exception:
        return False


def run_cmd_to_file(cmd: str, outpath: str, timeout: int = 600) -> str:
    """Run a shell command, write stdout+stderr to outpath, return combined output."""
    print(f"[+] RUN: {cmd}")
    try:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
        out = (out or "") + "[timeout]"
    except Exception as e:
        out = f"[error running command: {e}]"
    try:
        with open(outpath, "w", encoding="utf-8", errors="ignore") as f:
            f.write(f"$ {cmd}")
            f.write(out or "")
    except Exception as e:
        print("[!] Failed to write output file:", outpath, e)
    return out or ""


# ----------------- Scanners (nmap, whatweb) -----------------

def scanner_nmap(target: str, raw_dir: str, extra_args: str = "") -> Tuple[str, str]:
    out = os.path.join(raw_dir, "nmap.txt")
    cmd = f"nmap -Pn -sV {extra_args} {target}".strip()
    txt = run_cmd_to_file(cmd, out, timeout=600)
    return txt, out


def scanner_whatweb(target: str, raw_dir: str) -> Tuple[str, str]:
    out = os.path.join(raw_dir, "whatweb.txt")
    if not which("whatweb"):
        with open(out, "w", encoding="utf-8") as f:
            f.write("whatweb not installed")
        return "whatweb not installed", out
    cmd = f"whatweb --no-errors {target}"
    txt = run_cmd_to_file(cmd, out, timeout=300)
    return txt, out


# ----------------- Rule handling & matching -----------------

def load_rules_from_file(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "rules" in data:
        return data["rules"]
    if isinstance(data, list):
        return data
    raise ValueError("Rules file must be a JSON array or an object with 'rules' key")


def prepare_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize rule dictionary and compile regex if requested. Returns new dict with keys:
       id, match, match_type ('regex'|'substring'), compiled (optional), score, ...
    """
    r = dict(rule)  # shallow copy
    r.setdefault("match_type", "substring")
    r.setdefault("score", 5)
    r.setdefault("tools", [])

    # If user supplied match_type as 'regex', try compile.
    if r["match_type"] == "regex":
        try:
            r["compiled"] = re.compile(r.get("match", ""), re.I)
        except re.error:
            # invalid regex -> fallback to substring mode
            r["match_type"] = "substring"
            r.pop("compiled", None)
    else:
        # keep match lowercase for substring checks
        r["match_lower"] = r.get("match", "").lower()
    return r


def find_evidence_in_file(file_path: str, rule: Dict[str, Any], context_lines: int = 2, max_matches: int = 6) -> List[Dict[str, Any]]:
    evidence: List[Dict[str, Any]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return evidence

    compiled = rule.get("compiled")
    match_lower = rule.get("match_lower")

    for idx, line in enumerate(lines):
        matched = False
        if compiled:
            if compiled.search(line):
                matched = True
        elif match_lower:
            if match_lower in line.lower():
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


def predict_risk_level(score: float) -> str:
    try:
        s = float(score)
    except Exception:
        s = 0.0
    if s >= 9:
        return "Critical"
    if s >= 7:
        return "High"
    if s >= 4:
        return "Medium"
    return "Low"


# ----------------- Reporting -----------------

def save_reports(matches: List[Dict[str, Any]], output_name: str, run_folder: str, raw_files: List[str], json_report: bool = False) -> None:
    txt_path = os.path.join(run_folder, output_name)
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(f"WebRisk Smart Report generated: {now_ts()}")
        for m in matches:
            f.write(f"ID: {m['id']} | Title: {m.get('name', m.get('id',''))} | Score: {m.get('score')} | Level: {m.get('level')}")
            if m.get('severity'):
                f.write(f"Severity: {m.get('severity')} | Confidence: {m.get('confidence','')}")
            if m.get('recommendation'):
                f.write(f"Recommendation: {m.get('recommendation')}")
            f.write("Evidence:")
            for ev in m.get('evidence', []):
                f.write(f" - {ev['file']}:{ev['line_no']}: {ev['snippet']}")
            f.write("-" * 70 + "")
    print(f"[+] Saved text report: {txt_path}")

    if json_report:
        jpath = os.path.join(run_folder, "report.json")
        with open(jpath, "w", encoding="utf-8") as f:
            json.dump(matches, f, indent=2)
        print(f"[+] Saved JSON report: {jpath}")

    # Copy raw files
    raw_out_dir = os.path.join(run_folder, "raw")
    safe_mkdir(raw_out_dir)
    for rf in raw_files:
        if not rf:
            continue
        try:
            shutil.copy(rf, os.path.join(raw_out_dir, os.path.basename(rf)))
        except Exception:
            try:
                with open(rf, "r", encoding="utf-8", errors="ignore") as src:
                    txt = src.read()
                with open(os.path.join(raw_out_dir, os.path.basename(rf)), "w", encoding="utf-8") as dst:
                    dst.write(txt)
            except Exception:
                pass

    print(f"[+] All outputs saved in: {run_folder}")


# ----------------- Core flow -----------------

def create_results_folder(scan_type: str) -> str:
    base = os.path.join("Results_output", scan_type)
    safe_mkdir(base)
    run = os.path.join(base, now_ts())
    safe_mkdir(run)
    return run


def process_target(target: str, rules: List[Dict[str, Any]], args: argparse.Namespace) -> None:
    run_folder = create_results_folder("WebScan")

    # --- Capture (copy) the rules file used into the run folder for auditing ---
    if getattr(args, 'rules', None):
        try:
            rules_src = args.rules
            if os.path.exists(rules_src):
                dest_rules = os.path.join(run_folder, os.path.basename(rules_src))
                shutil.copy(rules_src, dest_rules)
                # write a SHA256 checksum for traceability
                try:
                    import hashlib
                    h = hashlib.sha256()
                    with open(dest_rules, 'rb') as rf:
                        for chunk in iter(lambda: rf.read(8192), b''):
                            h.update(chunk)
                    with open(os.path.join(run_folder, 'rules.sha256'), 'w', encoding='utf-8') as sf:
                        sf.write(f"{h.hexdigest()}  {os.path.basename(rules_src)}")
                except Exception:
                    pass
        except Exception:
            # non-fatal; continue without failing the scan
            pass

    # Ping pre-check
    if not args.skip_ping:
        print(f"[+] Pinging {target} ...")
        if not ping_target(target):
            print(f"[!] Ping to {target} failed or ICMP blocked. Use --skip-ping to bypass.")
            with open(os.path.join(run_folder, "README.txt"), "w", encoding="utf-8") as f:
                f.write(f"Target: {target}Timestamp: {now_ts()}PingCheck: FAILED")
            return
        else:
            print("[+] Ping OK — proceeding.")
    else:
        print("[!] Skipping ping as requested.")

    raw_dir = os.path.join(run_folder, "raw")
    safe_mkdir(raw_dir)

    raw_files: List[str] = []
    ran_any = False

    # Nmap
    if args.run_nmap or not (args.run_nmap or args.run_whatweb):
        ran_any = True
        print("[*] Running nmap ...")
        _, nmap_path = scanner_nmap(target, raw_dir, extra_args=args.nmap_args or "")
        raw_files.append(nmap_path)

    # WhatWeb
    if args.run_whatweb or not (args.run_nmap or args.run_whatweb):
        ran_any = True
        print("[*] Running whatweb ...")
        _, what_path = scanner_whatweb(target, raw_dir)
        raw_files.append(what_path)

    # Prepare & filter rules
    prepared = [prepare_rule(r) for r in rules]

    # Optionally filter rules by available scanners/tools
    available_tools = set()
    if which("nmap"):
        available_tools.add("nmap")
    if which("whatweb"):
        available_tools.add("whatweb")

    def rule_tool_allowed(r: Dict[str, Any]) -> bool:
        if not args.only_tools:
            return True
        wants = set([t.strip().lower() for t in r.get('tools', []) if isinstance(t, str)])
        check = set([t.strip().lower() for t in args.only_tools.split(',') if t.strip()])
        # allow if intersection
        return bool(wants & check)

    matches: List[Dict[str, Any]] = []
    for r in prepared:
        if args.only_tools and not rule_tool_allowed(r):
            continue
        if args.min_score and float(r.get('score', 0)) < float(args.min_score):
            continue

        evidence_total: List[Dict[str, Any]] = []
        for rf in raw_files:
            evidence_total.extend(find_evidence_in_file(rf, r, context_lines=args.context, max_matches=args.max_evidence))
            if len(evidence_total) >= args.max_evidence:
                break

        if evidence_total:
            match_entry = {
                'id': r.get('id', r.get('name', 'unknown')),
                'name': r.get('name', ''),
                'score': r.get('score', 5),
                'level': predict_risk_level(r.get('score', 5)),
                'severity': r.get('severity', ''),
                'confidence': r.get('confidence', ''),
                'recommendation': r.get('recommendation', r.get('note', '')),
                'evidence': evidence_total
            }
            matches.append(match_entry)
            if args.verbose:
                print(f"[MATCH] {match_entry['id']} (score={match_entry['score']}) — {len(evidence_total)} evidence items")

    # Save reports
    save_reports(matches, args.output, run_folder, raw_files, json_report=args.json_report)


# ----------------- CLI -----------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="WebRisk Smart (no nikto)")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('--target', help='Single target (domain or IP)')
    group.add_argument('--targets', help='File with targets, one per line')

    parser.add_argument('--rules', help='Rules JSON file (required).')
    parser.add_argument('--list-rules', action='store_true', help='List rules from the provided rules file and exit')
    parser.add_argument('--only-tools', help='Comma-separated tool names to filter rules by their tools field (e.g. whatweb,nmap)')
    parser.add_argument('--min-score', dest='min_score', type=float, default=0, help='Minimum rule score to consider')
    parser.add_argument('--max-evidence', dest='max_evidence', type=int, default=6, help='Maximum evidence items per rule')
    parser.add_argument('--context', dest='context', type=int, default=2, help='Context lines around matched line for evidence')

    parser.add_argument('-O', '--output', default='web_report.txt', help='Output text report filename')
    parser.add_argument('--json-report', action='store_true', help='Save JSON report alongside text')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    parser.add_argument('--run-nmap', action='store_true', help='Run nmap')
    parser.add_argument('--run-whatweb', action='store_true', help='Run whatweb')
    parser.add_argument('--skip-ping', action='store_true', help='Skip ping pre-check')
    parser.add_argument('--nmap-args', dest='nmap_args', help='Extra args to pass to nmap (quoted)')

    parser.add_argument('--max-evidence-global', dest='max_evidence_global', type=int, default=100, help=argparse.SUPPRESS)

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # simple greeting aligned with your preference
    print("Hello Fuad Hasan sir — WebRisk Smart starting.")

    # Rules file is required for this variant
    if not args.rules:
        print("[!] This build requires an external rules JSON file. Use --rules path/to/rules.json")
        sys.exit(1)

    if not os.path.exists(args.rules):
        print(f"[!] Rules file not found: {args.rules}")
        sys.exit(1)

    try:
        rules = load_rules_from_file(args.rules)
    except Exception as e:
        print("[!] Failed to load rules:", e)
        sys.exit(1)

    if args.list_rules:
        print("Available rules (id : match) — showing first 200 chars of match:")
        for r in rules:
            m = r.get('match','')
            print(f"{r.get('id','?')}: {m[:200]}")
        return

    # Validate targets
    targets: List[str] = []
    if args.target:
        targets = [args.target]
    elif args.targets:
        if not os.path.exists(args.targets):
            print(f"[!] Targets file not found: {args.targets}")
            sys.exit(1)
        with open(args.targets, 'r', encoding='utf-8') as f:
            targets = [ln.strip() for ln in f if ln.strip()]
    else:
        print("[!] Please specify --target or --targets")
        sys.exit(1)

    # Normalize and prepare rules now
    prepared_rules = [prepare_rule(r) for r in rules]

    # Reminder
    print("# Legal reminder: Only scan systems you own or have explicit permission to test.")

    for t in targets:
        print(f"=== Processing target: {t} ===")
        process_target(t, prepared_rules, args)


if __name__ == '__main__':
    main()
