#!/usr/bin/env python3
"""
webrisk 

This variant DOES NOT embed any rules. You must pass a rules JSON file with --rules.
Rules file format: either a JSON object with a "rules" array or a JSON array of rule objects.

Output: classic simple readable layout.
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
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def now_ts_fname() -> str:
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def safe_mkdir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences / color codes from text."""
    if not text:
        return text
    # Common robust ANSI escape remover
    return re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', text)


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
    # strip ANSI before writing raw file? keep raw but also store cleaned for report parsing
    try:
        with open(outpath, "w", encoding="utf-8", errors="ignore") as f:
            f.write(f"$ {cmd}\n")
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
            f.write("whatweb not installed\n")
        return "whatweb not installed\n", out
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
    """Normalize rule dictionary and compile regex if requested."""
    r = dict(rule)  # shallow copy
    r.setdefault("match_type", "substring")
    r.setdefault("score", 5)
    r.setdefault("tools", [])

    if r["match_type"] == "regex":
        try:
            r["compiled"] = re.compile(r.get("match", ""), re.I)
        except re.error:
            r["match_type"] = "substring"
            r.pop("compiled", None)
    else:
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
        # sanitize line of ANSI so matching is reliable
        clean_line = strip_ansi(line)
        matched = False
        if compiled:
            if compiled.search(clean_line):
                matched = True
        elif match_lower:
            if match_lower in clean_line.lower():
                matched = True

        if matched:
            start = max(0, idx - context_lines)
            end = min(len(lines), idx + context_lines + 1)
            snippet = "".join(lines[start:end])
            snippet = strip_ansi(snippet).strip()
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


# ----------------- Raw summary helpers -----------------

def summarize_raw_outputs(raw_files: List[str]) -> Dict[str, Optional[str]]:
    """Try to extract a simple status code and country hint from raw scanner outputs."""
    status = None
    country = None
    for rf in raw_files:
        try:
            with open(rf, "r", encoding="utf-8", errors="ignore") as f:
                txt = strip_ansi(f.read())
        except Exception:
            continue
        # Look for patterns like: '200 OK' or HTTP/... " 200
        m = re.search(r'\b(\d{3})\s+OK\b', txt)
        if not m:
            m = re.search(r'HTTP/\d\.\d"\s+(\d{3})', txt)
        if m and not status:
            code = m.group(1)
            status = f"{code} OK" if code == "200" else code

        # Look for 'Country' label produced by some fingerprinting outputs
        m2 = re.search(r'Country[:\s]*([A-Za-z \-]{2,40})', txt, re.I)
        if m2 and not country:
            country = m2.group(1).strip()
        # stop early if both found
        if status and country:
            break
    return {"status": status, "country": country}


# ----------------- Reporting -----------------

def save_reports(matches: List[Dict[str, Any]], output_name: str, run_folder: str, raw_files: List[str], json_report: bool = False, target: Optional[str] = None) -> None:
    txt_path = os.path.join(run_folder, output_name)
    report_id = f"R{str(now_ts_fname()).replace('-','').replace(':','').replace('_','')[-6:]}"
    summary = summarize_raw_outputs(raw_files)

    # severity counts
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for m in matches:
        lvl = m.get("level", "Low")
        if lvl in counts:
            counts[lvl] += 1
        else:
            counts["Low"] += 1

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("=" * 41 + "\n")
        f.write("        WebRisk Smart Report\n")
        f.write("=" * 41 + "\n")
        f.write(f"Generated: {now_ts()}\n")
        f.write(f"Report ID: {report_id}\n")
        f.write(f"Target   : {target or 'N/A'}\n\n")

        f.write("-" * 41 + "\n")
        f.write("[+] Scan Summary\n")
        f.write("-" * 41 + "\n")
        f.write(f"[+] Status Code : {summary.get('status') or 'Unknown'}\n")
        f.write(f"[+] Country     : {summary.get('country') or 'Unknown'}\n")
        f.write(f"[+] Total Matches: {len(matches)}\n")
        f.write(f"[+] Critical: {counts['Critical']}  High: {counts['High']}  Medium: {counts['Medium']}  Low: {counts['Low']}\n")
        f.write("-" * 41 + "\n\n")

        if not matches:
            f.write("No rules matched the provided outputs.\n\n")
        else:
            # print matches in classic Format 1 style
            for m in matches:
                f.write("-" * 41 + "\n")
                f.write(f"[+] ID          : {m.get('id')}\n")
                f.write(f"[+] Title       : {m.get('name') or ''}\n")
                f.write(f"[+] Score       : {m.get('score')}\n")
                f.write(f"[+] Level       : {m.get('level')}\n")
                if m.get('severity'):
                    f.write(f"[+] Severity    : {m.get('severity')}\n")
                if m.get('confidence'):
                    f.write(f"[+] Confidence  : {m.get('confidence')}\n")
                if m.get('recommendation'):
                    f.write(f"[+] Recommendation: {m.get('recommendation')}\n")
                f.write(f"[+] Evidence:\n")
                for ev in m.get('evidence', []):
                    # ensure snippets are one-line or indented multi-line
                    snippet = ev.get('snippet', '').strip()
                    snippet = "\n    ".join(snippet.splitlines())
                    f.write(f" - {ev.get('file')}:{ev.get('line_no')}: {snippet}\n")
                f.write("\n")
        f.write("-" * 41 + "\n")
        f.write("End of Report ✅\n")
        f.write("=" * 41 + "\n")

    print(f"[+] Saved text report: {txt_path}")

    if json_report:
        jpath = os.path.join(run_folder, "report.json")
        try:
            with open(jpath, "w", encoding="utf-8") as f:
                json.dump({
                    "report_id": report_id,
                    "generated": now_ts(),
                    "target": target,
                    "matches": matches,
                    "summary": {"status": summary.get("status"), "country": summary.get("country"), "counts": counts}
                }, f, indent=2)
            print(f"[+] Saved JSON report: {jpath}")
        except Exception as e:
            print("[!] Failed to save JSON report:", e)

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
    run = os.path.join(base, now_ts_fname())
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
            pass

    # Ping pre-check
    if not args.skip_ping:
        print(f"[+] Pinging {target} ...")
        if not ping_target(target):
            print(f"[!] Ping to {target} failed or ICMP blocked. Use --skip-ping to bypass.")
            with open(os.path.join(run_folder, "README.txt"), "w", encoding="utf-8") as f:
                f.write(f"Target: {target}\nTimestamp: {now_ts()}\nPingCheck: FAILED\n")
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

    prepared = [prepare_rule(r) for r in rules]

    def rule_tool_allowed(r: Dict[str, Any]) -> bool:
        if not args.only_tools:
            return True
        wants = set([t.strip().lower() for t in r.get('tools', []) if isinstance(t, str)])
        check = set([t.strip().lower() for t in args.only_tools.split(',') if t.strip()])
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

    # Save reports (pass target to include in header)
    save_reports(matches, args.output, run_folder, raw_files, json_report=args.json_report, target=target)


# ----------------- CLI -----------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="WebRisk Smart (no nikto)")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('--target', help='Single target (domain or IP)')
    group.add_argument('--targets', help='File with targets, one per line')

    parser.add_argument('--rules', help='Rules JSON file (required).')
    parser.add_argument('--list-rules', action='store_true', dest='list_rules', help='List rules from the provided rules file and exit')
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

    print("WebRisk Smart starting.")

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

    prepared_rules = [prepare_rule(r) for r in rules]

    print("# Legal reminder: Only scan systems you own or have explicit permission to test.")

    for t in targets:
        print(f"=== Processing target: {t} ===")
        process_target(t, prepared_rules, args)


if __name__ == '__main__':
    main()
