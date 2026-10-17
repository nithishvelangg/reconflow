#!/usr/bin/env python3
"""
reconflow v2 — subdomain discovery, live host probing, port scanning,
URL/param collection, vuln scanning (nuclei), JS secret scanning, and
endpoint fuzzing (ffuf), chained with unified HTML reports and resumable runs.

Keeps every v1 flag working. New stages are opt-in so existing users
and CI don't suddenly need naabu/nuclei/gau/ffuf installed.

  Use responsibly. Only scan domains you own or that are explicitly
  in scope for a program you are authorized to test.
"""

import argparse
import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

from reconflow import (
    audits,
    batch,
    cache_audit,
    config,
    cve_correlate,
    dns_sec,
    github_leaks,
    js_endpoints,
    jwt_analyzer,
    modules,
    notify,
    params_analyzer,
    passive_lookup,
    permute_scale,
    report,
    sarif,
    scope,
    state,
    takeover,
    zone_transfer,
)


def run_subfinder(domain: str, output_dir: Path):
    if shutil.which("subfinder") is None:
        sys.exit("[!] subfinder not found on PATH. Install it from "
                 "https://github.com/projectdiscovery/subfinder")
    print(f"[*] Finding subdomains for {domain}...")
    proc = subprocess.run(["subfinder", "-d", domain, "-silent"],
                          capture_output=True, text=True)
    subs = {s.strip() for s in proc.stdout.splitlines() if s.strip()}
    subs.add(domain.strip().lower())  # always probe the apex domain itself
    subs = sorted(subs)
    (output_dir / "subdomains.txt").write_text("\n".join(subs), encoding="utf-8")
    print(f"[+] Found {len(subs)} subdomains")
    return subs


def run_httpx(subdomains, output_dir: Path, threads=None, timeout=None,
              keep_wildcard=False, headers=None):
    if shutil.which("httpx") is None:
        sys.exit("[!] httpx not found on PATH. Install it from "
                 "https://github.com/projectdiscovery/httpx")
    print("[*] Probing for live hosts...")
    cmd = ["httpx", "-silent", "-json", "-title", "-status-code", "-tech-detect"]
    if headers:
        print(f"[*] Custom HTTP headers active ({len(headers)}): " + "; ".join(headers))
        for h in headers:
            cmd += ["-H", h]
    if threads:
        cmd += ["-threads", str(threads)]
    if timeout:
        cmd += ["-timeout", str(timeout)]

    proc = subprocess.run(cmd, input="\n".join(subdomains), capture_output=True, text=True)
    records = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    if not keep_wildcard and records:
        fingerprints = Counter((r.get("status_code"), r.get("content_length")) for r in records)
        common_fp = {fp for fp, count in fingerprints.items()
                     if count > max(3, len(records) * 0.3)}
        before = len(records)
        records = [r for r in records
                   if (r.get("status_code"), r.get("content_length")) not in common_fp]
        filtered = before - len(records)
        if filtered:
            print(f"[+] Filtered {filtered} likely wildcard DNS false positives "
                  f"(use --keep-wildcard to disable)")

    live_hosts = [r.get("url") or r.get("input") for r in records]
    (output_dir / "live.txt").write_text("\n".join(live_hosts), encoding="utf-8")
    print(f"[+] {len(live_hosts)} hosts are alive")
    return live_hosts, records


def build_markdown_report(domain, output_dir: Path, subdomains, live_hosts, extra_lines=None):
    lines = [
        f"# reconflow report — {domain}", "",
        f"- Subdomains found: **{len(subdomains)}**",
        f"- Live hosts: **{len(live_hosts)}**",
    ]
    if extra_lines:
        lines += extra_lines
    (output_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description="reconflow — all-in-one bug bounty recon")
    ap.add_argument("-d", "--domain", help="target root domain (e.g. example.com)")
    ap.add_argument("-dL", "--targets-file", metavar="FILE",
                    help="path to file with target domains, one per line (batch mode)")
    ap.add_argument("-o", "--output", default="output")
    ap.add_argument("-c", "--config", help="path to custom config file (e.g., reconflow.yaml)")
    ap.add_argument("--resume", action="store_true", help="resume an interrupted scan")
    ap.add_argument("-H", "--header", action="append", default=[], metavar="HEADER",
                    help="custom HTTP header for httpx (repeatable), e.g. -H 'X-Bug-Bounty: user'")
    ap.add_argument("--threads", type=int)
    ap.add_argument("--timeout", type=int)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--keep-wildcard", action="store_true")
    ap.add_argument("--screenshots", action="store_true")

    # new stages — all opt-in
    ap.add_argument("--ports", action="store_true", help="port scan live hosts with naabu")
    ap.add_argument("--top-ports", type=int)
    ap.add_argument("--port-scan-type", choices=["connect", "syn"], default="connect",
                    help="naabu scan mode (default: connect — works without Npcap/root; "
                         "syn is faster but needs Npcap on Windows / raw sockets on Linux)")
    ap.add_argument("--urls", action="store_true",
                    help="collect historical URLs + params with gau")
    ap.add_argument("--vuln", action="store_true", help="run nuclei against live hosts")
    ap.add_argument("--severity", help="nuclei severity filter (comma-separated)")
    ap.add_argument("--templates", metavar="PATH",
                    help="custom nuclei template file or directory "
                         "(default: nuclei's built-in set)")
    ap.add_argument("--update-templates", action="store_true",
                    help="update nuclei's default templates before scanning")
    ap.add_argument("--secrets", action="store_true", help="scan JS files for leaked secrets")
    ap.add_argument("--fuzz", action="store_true", help="fuzz endpoints on live hosts with ffuf")
    ap.add_argument("--wordlist", help="wordlist for ffuf fuzzing")
    ap.add_argument("--audit", action="store_true",
                    help="run all defensive asset audits (cloud, ASN, headers, CNAME)")
    ap.add_argument("--cloud-assets", action="store_true",
                    help="detect cloud storage bucket references in discovered URLs and hosts")
    ap.add_argument("--asn", action="store_true",
                    help="map network ASN and IP ranges for live hosts via RDAP")
    ap.add_argument("--headers", action="store_true",
                    help="audit HTTP security headers and CORS configurations")
    ap.add_argument("--cname-check", action="store_true",
                    help="audit DNS CNAME records for external cloud service dependencies")
    ap.add_argument("--takeover", action="store_true",
                    help="confirm subdomain takeovers via HTTP fingerprint "
                         "(requires --cname-check)")
    ap.add_argument("--scope", metavar="FILE",
                    help="HackerOne/Bugcrowd scope file to filter discovered subdomains against")
    ap.add_argument("--github-leaks", action="store_true",
                    help="search public GitHub code for leaked references to the domain")
    ap.add_argument("--github-token", metavar="TOKEN",
                    help="GitHub PAT for --github-leaks (required, GitHub code search needs auth)")
    ap.add_argument("--cve-correlate", action="store_true",
                    help="cross-reference httpx-detected tech versions against NVD CVEs")
    ap.add_argument("--passive", action="store_true",
                    help="passive Shodan InternetDB lookup (free, no API key)")
    ap.add_argument("--censys-id", metavar="ID", help="Censys API ID for --passive (optional)")
    ap.add_argument("--censys-secret", metavar="SECRET",
                    help="Censys API secret for --passive (optional)")
    ap.add_argument("--perm-scale", action="store_true",
                    help="scaled subdomain permutation with HTTP confirmation (vs DNS-only check)")
    ap.add_argument("--perm-wordlist", metavar="PATH",
                    help="external wordlist for --perm-scale (SecLists-style, one word per line)")
    ap.add_argument("--perm-max", type=int, default=5000,
                    help="max permutation candidates to probe (default: 5000)")
    ap.add_argument("--ct-logs", action="store_true",
                    help="harvest subdomains from Certificate Transparency logs (crt.sh)")
    ap.add_argument("--sensitive-files", action="store_true",
                    help="audit live hosts for exposed sensitive files and dev artifacts")
    ap.add_argument("--waf", action="store_true",
                    help="fingerprint Web Application Firewalls (WAF) & reverse proxies")
    ap.add_argument("--sitemap", action="store_true",
                    help="harvest routes from /robots.txt and /sitemap.xml across live hosts")
    ap.add_argument("--email-security", action="store_true",
                    help="audit domain SPF and DMARC DNS policies for spoofing vulnerabilities")
    ap.add_argument("--diff", action="store_true",
                    help="compute differential changes against previous scan baseline")
    ap.add_argument("--alterations", action="store_true",
                    help="generate intelligent subdomain permutations and test resolution")
    ap.add_argument("--ssl-audit", action="store_true",
                    help="audit SSL/TLS certificates for expiration, self-signed certs, and SANs")
    ap.add_argument("--favicon", action="store_true",
                    help="fingerprint web application frameworks via favicon MD5 hashes")
    ap.add_argument("--security-txt", action="store_true",
                    help="harvest and parse RFC 9116 security.txt disclosure policies")
    ap.add_argument("--security-headers", action="store_true",
                    help="grade defensive HTTP response headers (A+ to F posture score)")
    ap.add_argument("--sarif", action="store_true",
                    help="export findings to SARIF v2.1.0 for GitHub Code Scanning")
    ap.add_argument("--axfr", "--zone-transfer", action="store_true", dest="zone_transfer",
                    help="audit authoritative nameservers for open DNS zone transfer (AXFR)")
    ap.add_argument("--jwt", metavar="TOKEN",
                    help="analyze a specific JWT token for AppSec vulnerabilities")
    ap.add_argument("--jwt-file", metavar="PATH",
                    help="analyze JWT tokens found in a text file")
    ap.add_argument("--jwt-audit", action="store_true",
                    help="extract and audit all JWT tokens found in JS secrets and endpoints")
    ap.add_argument("--js-endpoints", action="store_true",
                    help="extract API routes, REST endpoints, and GraphQL ops from JS bundles")
    ap.add_argument("--dns-sec", action="store_true",
                    help="audit DNSSEC, CAA records, and authoritative nameserver delegation")
    ap.add_argument("--cache-audit", action="store_true",
                    help="audit Web Cache Deception & CDN edge caching policies")
    ap.add_argument("--param-miner", action="store_true",
                    help="classify discovered parameters into high-value vulnerability matrices")
    ap.add_argument("--full", action="store_true",
                    help="shortcut for all discovery stages, audits, and HTML report")
    ap.add_argument("--html", action="store_true", help="also build an HTML report")
    ap.add_argument("--notify", metavar="WEBHOOK_URL",
                    help="Discord/Slack webhook to ping when done")

    args = ap.parse_args()

    if not args.domain and not args.targets_file:
        ap.error("one of the following arguments is required: -d/--domain or -dL/--targets-file")

    # Load configuration file (reconflow.yaml / json)
    cfg = config.load_config(args.config)
    cfg_defaults = cfg.get("defaults", {})

    # Apply configuration defaults if CLI arguments were not provided
    if args.threads is None:
        args.threads = cfg_defaults.get("threads")
    if args.timeout is None:
        args.timeout = cfg_defaults.get("timeout")
    if args.top_ports is None:
        args.top_ports = cfg_defaults.get("top_ports", 100)
    if not args.severity:
        args.severity = cfg_defaults.get("severity", "medium,high,critical")
    if not args.notify:
        args.notify = cfg.get("notify", {}).get("webhook_url")

    if args.full:
        args.ports = args.urls = args.vuln = args.secrets = args.fuzz = args.html = True
        args.audit = True
        args.ct_logs = True
        args.alterations = True
        args.diff = True
        args.cname_check = True
        args.takeover = True
        args.sarif = True
        args.zone_transfer = True
        args.jwt_audit = True
        args.js_endpoints = True
        args.dns_sec = True
        args.cache_audit = True
        args.param_miner = True

    if args.audit:
        args.cloud_assets = args.asn = args.headers = args.cname_check = True
        args.sensitive_files = args.waf = args.email_security = args.sitemap = True
        args.ssl_audit = args.favicon = args.security_txt = args.security_headers = True
        args.zone_transfer = True
        args.jwt_audit = True
        args.dns_sec = True
        args.cache_audit = True

    if args.targets_file:
        targets = batch.load_targets(args.targets_file)
        if not targets:
            sys.exit(f"[!] No valid targets found in {args.targets_file}")
        batch.run_batch(targets, lambda d: run_pipeline(d, args), Path(args.output))
    else:
        run_pipeline(args.domain, args)


def run_pipeline(domain: str, args) -> dict:
    output_dir = Path(args.output) / domain
    output_dir.mkdir(parents=True, exist_ok=True)

    sm = state.StateManager(output_dir, domain, resume=args.resume)

    leak_findings = []
    # Stage: GitHub Public Code Leak Search
    if args.github_leaks:
        if sm.is_completed("github_leaks") and (output_dir / "github_leaks.json").exists():
            print(f"[*] Resuming: loading GitHub leaks from {output_dir / 'github_leaks.json'}")
            try:
                leak_findings = json.loads(
                    (output_dir / "github_leaks.json").read_text(encoding="utf-8")
                )
            except Exception:
                leak_findings = github_leaks.search_github_leaks(
                    domain, output_dir, args.github_token
                )
        else:
            leak_findings = github_leaks.search_github_leaks(
                domain, output_dir, args.github_token
            )
            sm.mark_completed("github_leaks", {"found": len(leak_findings)})

    permutation_results = []

    # Stage 1: Subdomains
    if sm.is_completed("subdomains") and (output_dir / "subdomains.txt").exists():
        print(f"[*] Resuming: loading subdomains from {output_dir / 'subdomains.txt'}")
        subdomains = [line.strip() for line in (output_dir / "subdomains.txt")
                      .read_text(encoding="utf-8").splitlines() if line.strip()]
        if args.scope:
            scope_data = scope.load_scope(args.scope)
            subdomains, _ = scope.filter_in_scope(subdomains, scope_data, output_dir)
    else:
        subdomains = run_subfinder(domain, output_dir)
        if args.scope:
            scope_data = scope.load_scope(args.scope)
            subdomains, _ = scope.filter_in_scope(subdomains, scope_data, output_dir)
        if args.ct_logs:
            ct_subs = audits.fetch_ct_subdomains(domain, output_dir)
            subdomains = sorted(list(set(subdomains) | set(ct_subs)))
            (output_dir / "subdomains.txt").write_text("\n".join(subdomains), encoding="utf-8")
            print(f"[+] Combined total: {len(subdomains)} unique subdomains")
        if args.alterations:
            permutation_results = audits.generate_permutations(
                subdomains, domain, output_dir
            )
            subdomains = sorted(list(set(subdomains) | set(permutation_results)))
            (output_dir / "subdomains.txt").write_text("\n".join(subdomains), encoding="utf-8")
            print(f"[+] Post-permutations total: {len(subdomains)} unique subdomains")
        if args.scope and (args.ct_logs or args.alterations):
            scope_data = scope.load_scope(args.scope)
            subdomains, _ = scope.filter_in_scope(subdomains, scope_data, output_dir)
            (output_dir / "subdomains.txt").write_text("\n".join(subdomains), encoding="utf-8")
        if args.perm_scale:
            perm_scale_findings = permute_scale.generate_permutations_scaled(
                subdomains, domain, output_dir,
                wordlist_path=args.perm_wordlist, max_candidates=args.perm_max,
            )
            confirmed_hosts = [r["host"] for r in perm_scale_findings if "host" in r]
            subdomains = sorted(list(set(subdomains) | set(confirmed_hosts)))
            if args.scope:
                scope_data = scope.load_scope(args.scope)
                subdomains, _ = scope.filter_in_scope(subdomains, scope_data, output_dir)
            (output_dir / "subdomains.txt").write_text("\n".join(subdomains), encoding="utf-8")
            sm.mark_completed("perm_scale", {"confirmed": len(perm_scale_findings)})
        sm.mark_completed("subdomains", {"count": len(subdomains)})

    perm_scale_findings = []
    if args.perm_scale and (output_dir / "permutations_scaled.json").exists():
        try:
            perm_scale_findings = json.loads(
                (output_dir / "permutations_scaled.json").read_text(encoding="utf-8")
            )
        except Exception:
            pass

    httpx_records = []
    # Stage 2: Live Hosts
    if sm.is_completed("live_hosts") and (output_dir / "live.txt").exists():
        print(f"[*] Resuming: loading live hosts from {output_dir / 'live.txt'}")
        live_hosts = [line.strip() for line in (output_dir / "live.txt")
                      .read_text(encoding="utf-8").splitlines() if line.strip()]
        if (output_dir / "httpx_records.json").exists():
            try:
                httpx_records = json.loads(
                    (output_dir / "httpx_records.json").read_text(encoding="utf-8")
                )
            except Exception:
                pass
    else:
        live_hosts, httpx_records = run_httpx(
            subdomains, output_dir, args.threads, args.timeout, args.keep_wildcard,
            headers=args.header
        )
        try:
            (output_dir / "httpx_records.json").write_text(
                json.dumps(httpx_records, indent=2), encoding="utf-8"
            )
        except Exception:
            pass
        sm.mark_completed("live_hosts", {"count": len(live_hosts)})

    ports_by_host, urls, params = {}, [], []
    vuln_findings, secret_findings, fuzz_findings = [], [], []
    cloud_findings, asn_findings = [], {}
    header_findings, cname_findings = [], []
    sensitive_findings, waf_findings = [], []
    email_security, sitemap_routes, diff_data = {}, {}, {}
    ssl_findings, favicon_findings, security_grades = [], [], []
    security_txt = {}
    shodan_findings = []
    js_endpoints_data = {}
    dns_sec_data = {}
    cache_audit_data = []
    param_matrix_data = {}

    # Stage: Passive OSINT Lookups (Shodan InternetDB, optional Censys)
    if args.passive and live_hosts:
        if sm.is_completed("passive") and (output_dir / "shodan_passive.json").exists():
            print(f"[*] Resuming: loading passive lookup from {output_dir / 'shodan_passive.json'}")
            try:
                shodan_findings = json.loads(
                    (output_dir / "shodan_passive.json").read_text(encoding="utf-8")
                )
            except Exception:
                shodan_findings = passive_lookup.shodan_internetdb_lookup(live_hosts, output_dir)
        else:
            shodan_findings = passive_lookup.shodan_internetdb_lookup(live_hosts, output_dir)
            if args.censys_id:
                passive_lookup.censys_lookup(
                    live_hosts, output_dir, args.censys_id, args.censys_secret
                )
            sm.mark_completed("passive", {"hosts_with_data": len(shodan_findings)})

    # Stage 3: Port Scan
    if args.ports and live_hosts:
        if sm.is_completed("ports") and (output_dir / "ports.json").exists():
            print(f"[*] Resuming: loading ports from {output_dir / 'ports.json'}")
            try:
                ports_by_host = json.loads((output_dir / "ports.json").read_text(encoding="utf-8"))
            except Exception:
                ports_by_host = modules.port_scan(
                    live_hosts, output_dir, args.top_ports,
                    scan_type=getattr(args, "port_scan_type", "connect"),
                )
        else:
            ports_by_host = modules.port_scan(
                live_hosts, output_dir, args.top_ports,
                scan_type=getattr(args, "port_scan_type", "connect"),
            )
            sm.mark_completed("ports", {"hosts_with_ports": len(ports_by_host)})

    # Stage 4: Historical URLs & Params
    if args.urls:
        if sm.is_completed("urls") and (output_dir / "urls.txt").exists():
            print(f"[*] Resuming: loading URLs from {output_dir / 'urls.txt'}")
            urls = [line.strip() for line in (output_dir / "urls.txt")
                    .read_text(encoding="utf-8").splitlines() if line.strip()]
            if (output_dir / "params.txt").exists():
                params = [line.strip() for line in (output_dir / "params.txt")
                          .read_text(encoding="utf-8").splitlines() if line.strip()]
        else:
            urls, params = modules.url_collect(domain, output_dir)
            sm.mark_completed("urls", {"urls_count": len(urls), "params_count": len(params)})

    # Stage 5: Vulnerability Scan
    if args.vuln and live_hosts:
        if sm.is_completed("vuln") and (output_dir / "vulns.json").exists():
            print(f"[*] Resuming: loading vulnerabilities from {output_dir / 'vulns.json'}")
            try:
                lines = (output_dir / "vulns.json").read_text(encoding="utf-8").splitlines()
                vuln_findings = [json.loads(line) for line in lines if line.strip()]
            except Exception:
                vuln_findings = modules.vuln_scan(
                    live_hosts, output_dir, args.severity,
                    templates=args.templates, update_templates=args.update_templates,
                )
        else:
            vuln_findings = modules.vuln_scan(
                live_hosts, output_dir, args.severity,
                templates=args.templates, update_templates=args.update_templates,
            )
            sm.mark_completed("vuln", {"findings_count": len(vuln_findings)})

    # Stage 6: Secret Scan
    if args.secrets:
        if sm.is_completed("secrets") and (output_dir / "secrets.json").exists():
            print(f"[*] Resuming: loading secrets from {output_dir / 'secrets.json'}")
            try:
                secret_findings = json.loads(
                    (output_dir / "secrets.json").read_text(encoding="utf-8")
                )
            except Exception:
                js_source = urls if urls else live_hosts
                secret_findings = modules.secret_scan(js_source, output_dir)
        else:
            js_source = urls if urls else live_hosts
            secret_findings = modules.secret_scan(js_source, output_dir)
            sm.mark_completed("secrets", {"secrets_count": len(secret_findings)})

    jwt_findings = []
    # Stage: JSON Web Token (JWT) Security Analysis
    if (getattr(args, "jwt_audit", False) or getattr(args, "jwt", None)
            or getattr(args, "jwt_file", None)):
        if sm.is_completed("jwt_analysis") and (output_dir / "jwt_analysis.json").exists():
            print(f"[*] Resuming: loading JWT analysis from {output_dir / 'jwt_analysis.json'}")
            try:
                jwt_findings = json.loads(
                    (output_dir / "jwt_analysis.json").read_text(encoding="utf-8")
                )
            except Exception:
                jwt_findings = []
        else:
            jwt_tokens = []
            if getattr(args, "jwt", None):
                jwt_tokens.append(args.jwt)
            if getattr(args, "jwt_file", None):
                p = Path(args.jwt_file)
                if p.exists():
                    jwt_tokens.extend(
                        jwt_analyzer.extract_jwts(p.read_text(encoding="utf-8", errors="ignore"))
                    )
            if getattr(args, "jwt_audit", False):
                for s in secret_findings:
                    if s.get("type") == "JWT":
                        jwt_tokens.extend(jwt_analyzer.extract_jwts(s.get("match", "")))
            jwt_tokens = list(set(jwt_tokens))
            jwt_findings = jwt_analyzer.audit_jwts(jwt_tokens, output_dir, domain=domain)
            sm.mark_completed("jwt_analysis", {"audited": len(jwt_findings)})

    # Stage: JavaScript Endpoint & API Route Extractor
    if getattr(args, "js_endpoints", False):
        if sm.is_completed("js_endpoints") and (output_dir / "js_endpoints.json").exists():
            print(f"[*] Resuming: loading JS endpoints from {output_dir / 'js_endpoints.json'}")
            try:
                js_endpoints_data = json.loads(
                    (output_dir / "js_endpoints.json").read_text(encoding="utf-8")
                )
            except Exception:
                js_source = urls if urls else live_hosts
                js_endpoints_data = js_endpoints.extract_js_endpoints(
                    js_source, output_dir, domain=domain,
                    threads=args.threads or 10, timeout=args.timeout or 7
                )
        else:
            js_source = urls if urls else live_hosts
            js_endpoints_data = js_endpoints.extract_js_endpoints(
                js_source, output_dir, domain=domain,
                threads=args.threads or 10, timeout=args.timeout or 7
            )
            sm.mark_completed("js_endpoints", {
                "routes": js_endpoints_data.get("total_unique_routes", 0),
                "graphql": js_endpoints_data.get("total_graphql_ops", 0),
            })

    # Stage: Parameter Attack Surface Matrix
    if getattr(args, "param_miner", False):
        if sm.is_completed("param_miner") and (output_dir / "param_matrix.json").exists():
            print(f"[*] Resuming: loading parameter matrix from {output_dir / 'param_matrix.json'}")
            try:
                param_matrix_data = json.loads(
                    (output_dir / "param_matrix.json").read_text(encoding="utf-8")
                )
            except Exception:
                param_matrix_data = params_analyzer.analyze_parameters(params, urls, output_dir)
        else:
            param_matrix_data = params_analyzer.analyze_parameters(params, urls, output_dir)
            sm.mark_completed("param_miner", {
                "high_value": param_matrix_data.get("total_high_value_flagged", 0)
            })

    # Stage 7: Directory Fuzzing (ffuf)
    if args.fuzz and live_hosts:
        if sm.is_completed("fuzz") and (output_dir / "fuzz.json").exists():
            print(f"[*] Resuming: loading fuzzing results from {output_dir / 'fuzz.json'}")
            try:
                fuzz_findings = json.loads(
                    (output_dir / "fuzz.json").read_text(encoding="utf-8")
                )
            except Exception:
                fuzz_findings = modules.dir_fuzz(live_hosts, output_dir, args.wordlist)
        else:
            fuzz_findings = modules.dir_fuzz(live_hosts, output_dir, args.wordlist)
            sm.mark_completed("fuzz", {"endpoints_count": len(fuzz_findings)})

    # Stage 8: Screenshots (gowitness)
    if args.screenshots:
        if shutil.which("gowitness") is None:
            print("[!] gowitness not found on PATH — skipping screenshots.")
        else:
            shots_dir = output_dir / "screenshots"
            shots_dir.mkdir(exist_ok=True)
            subprocess.run(["gowitness", "file", "-f", str(output_dir / "live.txt"),
                            "-P", str(shots_dir)], capture_output=True)
            print(f"[+] Screenshots saved to {shots_dir}")
            sm.mark_completed("screenshots")

    # Stage 9: Cloud Storage Asset Detection
    if args.cloud_assets and (urls or live_hosts):
        if sm.is_completed("cloud_assets") and (output_dir / "cloud_assets.json").exists():
            print(f"[*] Resuming: loading cloud assets from {output_dir / 'cloud_assets.json'}")
            try:
                cloud_findings = json.loads(
                    (output_dir / "cloud_assets.json").read_text(encoding="utf-8")
                )
            except Exception:
                cloud_findings = audits.detect_cloud_assets(urls, live_hosts, output_dir)
        else:
            cloud_findings = audits.detect_cloud_assets(urls, live_hosts, output_dir)
            sm.mark_completed("cloud_assets", {"assets_count": len(cloud_findings)})

    # Stage 10: Network ASN & IP Range Mapping
    if args.asn and live_hosts:
        if sm.is_completed("asn") and (output_dir / "asn_ranges.json").exists():
            print(f"[*] Resuming: loading ASN mappings from {output_dir / 'asn_ranges.json'}")
            try:
                asn_findings = json.loads(
                    (output_dir / "asn_ranges.json").read_text(encoding="utf-8")
                )
            except Exception:
                asn_findings = audits.lookup_asn_ranges(live_hosts, output_dir)
        else:
            asn_findings = audits.lookup_asn_ranges(live_hosts, output_dir)
            sm.mark_completed("asn", {"ranges_count": len(asn_findings)})

    # Stage 11: HTTP Headers & CORS Configuration Audit
    if args.headers and live_hosts:
        if sm.is_completed("headers") and (output_dir / "headers_audit.json").exists():
            print(f"[*] Resuming: loading header audits from {output_dir / 'headers_audit.json'}")
            try:
                header_findings = json.loads(
                    (output_dir / "headers_audit.json").read_text(encoding="utf-8")
                )
            except Exception:
                header_findings = audits.audit_http_headers(live_hosts, output_dir)
        else:
            header_findings = audits.audit_http_headers(live_hosts, output_dir)
            sm.mark_completed("headers", {"audited_count": len(header_findings)})

    # Stage: Web Cache & CDN Policy Audit
    if getattr(args, "cache_audit", False) and live_hosts:
        if sm.is_completed("cache_audit") and (output_dir / "cache_audit.json").exists():
            print(f"[*] Resuming: loading cache audit from {output_dir / 'cache_audit.json'}")
            try:
                cache_audit_data = json.loads(
                    (output_dir / "cache_audit.json").read_text(encoding="utf-8")
                )
            except Exception:
                cache_audit_data = cache_audit.audit_cache_policies(
                    live_hosts, output_dir,
                    threads=args.threads or 10, timeout=args.timeout or 5
                )
        else:
            cache_audit_data = cache_audit.audit_cache_policies(
                live_hosts, output_dir,
                threads=args.threads or 10, timeout=args.timeout or 5
            )
            sm.mark_completed("cache_audit", {
                "audited": len(cache_audit_data),
                "vulnerable": sum(1 for c in cache_audit_data if c.get("is_vulnerable")),
            })

    # Stage 12: DNS CNAME Record Validation
    if args.cname_check and subdomains:
        if sm.is_completed("cname") and (output_dir / "cname_audit.json").exists():
            print(f"[*] Resuming: loading CNAME audit from {output_dir / 'cname_audit.json'}")
            try:
                cname_findings = json.loads(
                    (output_dir / "cname_audit.json").read_text(encoding="utf-8")
                )
            except Exception:
                cname_findings = audits.audit_cname_records(subdomains, output_dir)
        else:
            cname_findings = audits.audit_cname_records(subdomains, output_dir)
            sm.mark_completed("cname", {"flagged_count": len(cname_findings)})

    takeover_findings = []
    # Stage: Confirmed Subdomain Takeover
    if args.takeover:
        if not args.cname_check:
            print("[!] --takeover requires --cname-check to run first (needs its output) "
                  "— skipping.")
        elif sm.is_completed("takeover") and (output_dir / "takeover_confirmed.json").exists():
            print(f"[*] Resuming: loading takeover results from "
                  f"{output_dir / 'takeover_confirmed.json'}")
            try:
                takeover_findings = json.loads(
                    (output_dir / "takeover_confirmed.json").read_text(encoding="utf-8")
                )
            except Exception:
                takeover_findings = takeover.detect_subdomain_takeovers(cname_findings, output_dir)
        else:
            takeover_findings = takeover.detect_subdomain_takeovers(cname_findings, output_dir)
            sm.mark_completed("takeover", {"confirmed": len(takeover_findings)})

    # Stage 13: Exposed Sensitive Files & Dev Artifacts
    if args.sensitive_files and live_hosts:
        if sm.is_completed("sensitive_files") and (output_dir / "sensitive_files.json").exists():
            print(f"[*] Resuming: loading sensitive files from "
                  f"{output_dir / 'sensitive_files.json'}")
            try:
                sensitive_findings = json.loads(
                    (output_dir / "sensitive_files.json").read_text(encoding="utf-8")
                )
            except Exception:
                sensitive_findings = audits.audit_sensitive_files(live_hosts, output_dir)
        else:
            sensitive_findings = audits.audit_sensitive_files(live_hosts, output_dir)
            sm.mark_completed("sensitive_files", {"findings": len(sensitive_findings)})

    # Stage 14: WAF & Reverse Proxy Detection
    if args.waf and live_hosts:
        if sm.is_completed("waf") and (output_dir / "waf_detection.json").exists():
            print(f"[*] Resuming: loading WAF detection from {output_dir / 'waf_detection.json'}")
            try:
                waf_findings = json.loads(
                    (output_dir / "waf_detection.json").read_text(encoding="utf-8")
                )
            except Exception:
                waf_findings = audits.detect_waf(live_hosts, output_dir)
        else:
            waf_findings = audits.detect_waf(live_hosts, output_dir)
            sm.mark_completed("waf", {"fingerprinted": len(waf_findings)})

    # Stage 15: Robots.txt & Sitemap Harvesting
    if args.sitemap and live_hosts:
        if sm.is_completed("sitemap") and (output_dir / "sitemap_routes.json").exists():
            print(f"[*] Resuming: loading sitemap routes from {output_dir / 'sitemap_routes.json'}")
            try:
                sitemap_routes = json.loads(
                    (output_dir / "sitemap_routes.json").read_text(encoding="utf-8")
                )
            except Exception:
                sitemap_routes = audits.harvest_sitemaps(live_hosts, output_dir)
        else:
            sitemap_routes = audits.harvest_sitemaps(live_hosts, output_dir)
            sm.mark_completed("sitemap", {"hosts": len(sitemap_routes)})

    # Stage 16: Email Security & DNS Governance
    if args.email_security:
        if sm.is_completed("email_sec") and (output_dir / "email_security.json").exists():
            print(f"[*] Resuming: loading email security from "
                  f"{output_dir / 'email_security.json'}")
    zone_transfer_findings = []
    # Stage: DNS Zone Transfer (AXFR) Misconfiguration
    if getattr(args, "zone_transfer", False):
        if sm.is_completed("zone_transfer") and (output_dir / "zone_transfer.json").exists():
            print(f"[*] Resuming: loading zone transfer from {output_dir / 'zone_transfer.json'}")
            try:
                zone_transfer_findings = json.loads(
                    (output_dir / "zone_transfer.json").read_text(encoding="utf-8")
                )
            except Exception:
                zone_transfer_findings = zone_transfer.audit_zone_transfer(
                    domain, output_dir, timeout=args.timeout or 5
                )
        else:
            zone_transfer_findings = zone_transfer.audit_zone_transfer(
                domain, output_dir, timeout=args.timeout or 5
            )
            sm.mark_completed("zone_transfer", {
                "tested": len(zone_transfer_findings),
                "vulnerable": sum(1 for z in zone_transfer_findings if z.get("vulnerable")),
            })

    # Stage 16: Email Security & DNS Governance
    if args.email_security:
        if sm.is_completed("email_sec") and (output_dir / "email_security.json").exists():
            print(f"[*] Resuming: loading email security from "
                  f"{output_dir / 'email_security.json'}")
            try:
                email_security = json.loads(
                    (output_dir / "email_security.json").read_text(encoding="utf-8")
                )
            except Exception:
                email_security = audits.audit_email_security(domain, output_dir)
        else:
            email_security = audits.audit_email_security(domain, output_dir)
            sm.mark_completed("email_sec", {
                "spf": email_security.get("spf", {}).get("status"),
                "dmarc": email_security.get("dmarc", {}).get("policy"),
            })

    # Stage 17: Differential Recon Change Detection
    if args.diff:
        diff_data = audits.compute_differential(
            output_dir, domain, subdomains, live_hosts, ports_by_host
        )

    # Stage 18: SSL/TLS Certificate Security Audit
    if args.ssl_audit and live_hosts:
        if sm.is_completed("ssl_audit") and (output_dir / "ssl_audit.json").exists():
            print(f"[*] Resuming: loading SSL audit from {output_dir / 'ssl_audit.json'}")
            try:
                ssl_findings = json.loads(
                    (output_dir / "ssl_audit.json").read_text(encoding="utf-8")
                )
            except Exception:
                ssl_findings = audits.audit_ssl_certificates(live_hosts, output_dir)
        else:
            ssl_findings = audits.audit_ssl_certificates(live_hosts, output_dir)
            sm.mark_completed("ssl_audit", {"audited": len(ssl_findings)})

    # Stage 19: Favicon Technology Fingerprinting
    if args.favicon and live_hosts:
        if sm.is_completed("favicon") and (output_dir / "favicon_fingerprints.json").exists():
            print(f"[*] Resuming: loading favicons from {output_dir / 'favicon_fingerprints.json'}")
            try:
                favicon_findings = json.loads(
                    (output_dir / "favicon_fingerprints.json").read_text(encoding="utf-8")
                )
            except Exception:
                favicon_findings = audits.fingerprint_favicons(live_hosts, output_dir)
        else:
            favicon_findings = audits.fingerprint_favicons(live_hosts, output_dir)
            sm.mark_completed("favicon", {"fingerprinted": len(favicon_findings)})

    # Stage 20: RFC 9116 Security.txt Policy Harvester
    if args.security_txt:
        if sm.is_completed("security_txt") and (output_dir / "security_txt.json").exists():
            print(f"[*] Resuming: loading security.txt from {output_dir / 'security_txt.json'}")
            try:
                security_txt = json.loads(
                    (output_dir / "security_txt.json").read_text(encoding="utf-8")
                )
            except Exception:
                security_txt = audits.harvest_security_txt(domain, live_hosts, output_dir)
        else:
            security_txt = audits.harvest_security_txt(domain, live_hosts, output_dir)
            sm.mark_completed("security_txt", {"found": security_txt.get("found", False)})

    # Stage 21: Defensive HTTP Response Header Grading
    if args.security_headers and live_hosts:
        if sm.is_completed("sec_headers") and (output_dir / "security_grades.json").exists():
            print(f"[*] Resuming: loading header grades from {output_dir / 'security_grades.json'}")
            try:
                security_grades = json.loads(
                    (output_dir / "security_grades.json").read_text(encoding="utf-8")
                )
            except Exception:
                security_grades = audits.grade_security_headers(live_hosts, output_dir)
        else:
            security_grades = audits.grade_security_headers(live_hosts, output_dir)
            sm.mark_completed("sec_headers", {"graded": len(security_grades)})

    cve_findings = []
    # Stage: Tech-Stack CVE Correlation
    if args.cve_correlate:
        if sm.is_completed("cve_correlate") and (output_dir / "cve_correlation.json").exists():
            print(f"[*] Resuming: loading CVE correlation from "
                  f"{output_dir / 'cve_correlation.json'}")
            try:
                cve_findings = json.loads(
                    (output_dir / "cve_correlation.json").read_text(encoding="utf-8")
                )
            except Exception:
                cve_findings = cve_correlate.correlate_cves(httpx_records, output_dir)
        else:
            cve_findings = cve_correlate.correlate_cves(httpx_records, output_dir)
            sm.mark_completed("cve_correlate", {"technologies_flagged": len(cve_findings)})

    # Stage: DNSSEC, CAA & Dangling Nameserver Audit
    if getattr(args, "dns_sec", False):
        if sm.is_completed("dns_sec") and (output_dir / "dns_audit.json").exists():
            print(f"[*] Resuming: loading DNS security audit from {output_dir / 'dns_audit.json'}")
            try:
                dns_sec_data = json.loads(
                    (output_dir / "dns_audit.json").read_text(encoding="utf-8")
                )
            except Exception:
                dns_sec_data = dns_sec.audit_dns_security(domain, output_dir)
        else:
            dns_sec_data = dns_sec.audit_dns_security(domain, output_dir)
            sm.mark_completed("dns_sec", {
                "dnssec": dns_sec_data.get("dnssec", {}).get("status"),
                "has_dangling_ns": dns_sec_data.get("nameservers", {}).get(
                    "has_dangling_ns", False
                ),
            })

    extra_md = []
    if dns_sec_data:
        ns_sec = dns_sec_data.get("nameservers", {})
        if ns_sec.get("has_dangling_ns"):
            extra_md.append(
                f"- Dangling Nameservers: **{len(ns_sec.get('dangling_nameservers', []))}**"
            )
    if ports_by_host:
        extra_md.append(f"- Hosts with open ports: **{len(ports_by_host)}**")
    if urls:
        extra_md.append(f"- URLs collected: **{len(urls)}** ({len(params)} unique params)")
    if vuln_findings:
        extra_md.append(f"- Vulnerability findings: **{len(vuln_findings)}**")
    if secret_findings:
        extra_md.append(f"- Potential secrets found: **{len(secret_findings)}**")
    if fuzz_findings:
        extra_md.append(f"- Discovered endpoints: **{len(fuzz_findings)}**")
    if cloud_findings:
        extra_md.append(f"- Cloud storage references: **{len(cloud_findings)}**")
    if asn_findings:
        extra_md.append(f"- Network ranges mapped: **{len(asn_findings)}**")
    if header_findings:
        extra_md.append(f"- Audited HTTP endpoints: **{len(header_findings)}**")
    if cname_findings:
        extra_md.append(f"- External service CNAMEs: **{len(cname_findings)}**")
    if takeover_findings:
        extra_md.append(f"- Confirmed subdomain takeovers: **{len(takeover_findings)}**")
    if leak_findings:
        extra_md.append(f"- Potential GitHub code references: **{len(leak_findings)}**")
    if cve_findings:
        total_cves = sum(len(f.get("cves", [])) for f in cve_findings)
        extra_md.append(
            f"- Tech-stack CVEs: **{total_cves}** across {len(cve_findings)} technologies"
        )
    if shodan_findings:
        shodan_vulns = sum(len(r.get("vulns", [])) for r in shodan_findings)
        extra_md.append(f"- Shodan passive hosts: **{len(shodan_findings)}** ({shodan_vulns} CVEs)")
    if perm_scale_findings:
        extra_md.append(f"- Scaled HTTP permutations: **{len(perm_scale_findings)}**")
    if sensitive_findings:
        extra_md.append(f"- Exposed sensitive files: **{len(sensitive_findings)}**")
    if waf_findings:
        protected = sum(1 for w in waf_findings if w.get("protected"))
        extra_md.append(f"- WAF / CDN protected hosts: **{protected}/{len(waf_findings)}**")
    if email_security:
        spf_st = email_security.get("spf", {}).get("status", "N/A")
        dmarc_pol = email_security.get("dmarc", {}).get("policy", "N/A")
        extra_md.append(f"- Email Security: SPF (**{spf_st}**), DMARC (**{dmarc_pol}**)")
    if diff_data and diff_data.get("has_baseline"):
        extra_md.append(
            f"- Differential changes: **+{len(diff_data.get('new_subdomains', []))}** new subs, "
            f"**+{len(diff_data.get('new_live_hosts', []))}** new live"
        )
    if ssl_findings:
        warn_ssl = sum(1 for s in ssl_findings if s.get("self_signed") or s.get("expiring_soon"))
        extra_md.append(f"- SSL/TLS certs audited: **{len(ssl_findings)}** ({warn_ssl} warnings)")
    if favicon_findings:
        matched_fav = sum(1 for f in favicon_findings if f.get("matched"))
        extra_md.append(f"- Favicons matched: **{matched_fav}/{len(favicon_findings)}**")
    if security_txt and security_txt.get("found"):
        extra_md.append(f"- RFC 9116 security.txt: **Disclosed** ({security_txt.get('url')})")
    if security_grades:
        avg_score = int(sum(g["score"] for g in security_grades) / len(security_grades))
        extra_md.append(f"- Defensive header posture: **{avg_score}/100 average grade**")

    if zone_transfer_findings:
        vuln_axfr = sum(1 for z in zone_transfer_findings if z.get("vulnerable"))
        extra_md.append(
            f"- DNS Zone Transfer (AXFR): **{len(zone_transfer_findings)} nameservers tested** "
            f"({vuln_axfr} vulnerable)"
        )
    if jwt_findings:
        crit_jwts = sum(1 for j in jwt_findings if j.get("risk_level") == "CRITICAL")
        extra_md.append(
            f"- JWT Security Analysis: **{len(jwt_findings)} tokens analyzed** "
            f"({crit_jwts} critical flaws)"
        )

    build_markdown_report(domain, output_dir, subdomains, live_hosts, extra_md)

    if args.json:
        (output_dir / "report.json").write_text(json.dumps({
            "domain": domain,
            "subdomains": subdomains,
            "live_hosts": live_hosts,
            "ports": ports_by_host,
            "urls": urls,
            "params": params,
            "vulnerabilities": vuln_findings,
            "secrets": secret_findings,
            "endpoints": fuzz_findings,
            "cloud_assets": cloud_findings,
            "asn_ranges": asn_findings,
            "headers_audit": header_findings,
            "cname_audit": cname_findings,
            "takeover_confirmed": takeover_findings,
            "github_leaks": leak_findings,
            "cve_correlation": cve_findings,
            "shodan_passive": shodan_findings,
            "permutations_scaled": perm_scale_findings,
            "sensitive_files": sensitive_findings,
            "waf_detection": waf_findings,
            "sitemap_routes": sitemap_routes,
            "email_security": email_security,
            "differential": diff_data,
            "ssl_audit": ssl_findings,
            "favicon_fingerprints": favicon_findings,
            "security_txt": security_txt,
            "security_grades": security_grades,
            "permutations": permutation_results,
            "zone_transfer": zone_transfer_findings,
            "jwt_analysis": jwt_findings,
        }, indent=2), encoding="utf-8")

    if args.html:
        report.build_html_report(
            domain, output_dir, subdomains, live_hosts,
            ports_by_host=ports_by_host,
            vuln_findings=vuln_findings,
            secret_findings=secret_findings,
            fuzz_findings=fuzz_findings,
            url_count=len(urls),
            param_count=len(params),
            cloud_findings=cloud_findings,
            cname_findings=cname_findings,
            sensitive_findings=sensitive_findings,
            waf_findings=waf_findings,
            email_security=email_security,
            diff_data=diff_data,
            route_count=len(sitemap_routes),
            ssl_findings=ssl_findings,
            favicon_findings=favicon_findings,
            security_grades=security_grades,
            security_txt=security_txt,
            permutation_count=len(permutation_results),
            zone_transfer=zone_transfer_findings,
            jwt_findings=jwt_findings,
            js_endpoints=js_endpoints_data,
            dns_sec=dns_sec_data,
            cache_audits=cache_audit_data,
            param_matrix=param_matrix_data,
        )

    if getattr(args, "sarif", False):
        sarif_findings = {
            "takeovers": takeover_findings,
            "vulns": vuln_findings,
            "secrets": secret_findings,
            "sensitive_files": sensitive_findings,
            "zone_transfers": zone_transfer_findings,
            "jwts": jwt_findings,
            "cves": cve_findings,
            "email_security": email_security,
        }
        sarif.generate_sarif(domain, output_dir, sarif_findings)

    stats_dict = {
        "Subdomains": len(subdomains),
        "Live hosts": len(live_hosts),
        "Vuln findings": len(vuln_findings),
        "Potential secrets": len(secret_findings),
        "Endpoints": len(fuzz_findings),
    }
    if cloud_findings:
        stats_dict["Cloud assets"] = len(cloud_findings)
    if cname_findings:
        stats_dict["Service CNAMEs"] = len(cname_findings)
    if takeover_findings:
        stats_dict["Confirmed takeovers"] = len(takeover_findings)
    if leak_findings:
        stats_dict["GitHub leaks"] = len(leak_findings)
    if cve_findings:
        stats_dict["Tech CVEs"] = len(cve_findings)
    if shodan_findings:
        stats_dict["Shodan hosts"] = len(shodan_findings)
    if perm_scale_findings:
        stats_dict["Permutations confirmed"] = len(perm_scale_findings)
    if sensitive_findings:
        stats_dict["Sensitive files"] = len(sensitive_findings)
    if diff_data and diff_data.get("new_subdomains"):
        stats_dict["New subdomains"] = len(diff_data["new_subdomains"])
    if ssl_findings:
        stats_dict["SSL hosts"] = len(ssl_findings)
    if zone_transfer_findings:
        stats_dict["Open AXFR"] = sum(1 for z in zone_transfer_findings if z.get("vulnerable"))
    if jwt_findings:
        stats_dict["Critical JWTs"] = sum(
            1 for j in jwt_findings if j.get("risk_level") == "CRITICAL"
        )

    if args.notify:
        notify.send_webhook(args.notify, domain, stats_dict)

    print(f"[+] Report saved to {output_dir / 'report.md'}")
    return stats_dict


if __name__ == "__main__":
    main()
