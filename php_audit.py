#!/usr/bin/env python3
"""Richtofen PHP2Shell Detector | Author: 0xRichtofen"""
import argparse
import concurrent.futures
import csv
import time
import json
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

VERSION = "3.1.0"
AUTHOR = "0xRichtofen"
FIXES = {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}
CVES = ("CVE-2026-109618", "CVE-2026-109619")
PATTERN = re.compile(r"\bPHP[/ ](\d+)\.(\d+)\.(\d+)\b", re.I)


def normalize(raw):
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    raw = raw.split()[0]
    if "://" not in raw:
        raw = "https://" + raw
    u = urllib.parse.urlsplit(raw)
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
        raise ValueError("invalid URL")
    if u.port is not None and not 1 <= u.port <= 65535:
        raise ValueError("invalid port")
    return urllib.parse.urlunsplit((u.scheme, u.netloc, u.path or "/", u.query, ""))


def classify(version):
    if not version:
        return "UNKNOWN"
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version)
    if not m:
        return "UNKNOWN"
    major, minor, patch = map(int, m.groups())
    branch = f"{major}.{minor}"
    if branch in FIXES:
        return "UPSTREAM_FIXED_VERSION" if patch >= FIXES[branch] else "BELOW_UPSTREAM_FIX"
    if (major, minor) < (8, 2):
        return "LEGACY_BRANCH_REVIEW"
    return "NOT_IN_VERSION_TABLE"


class SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urllib.parse.urlsplit(req.full_url)
        new = urllib.parse.urlsplit(newurl)
        def port(u):
            return u.port or (443 if u.scheme == "https" else 80)
        if (old.scheme, old.hostname, port(old)) != (new.scheme, new.hostname, port(new)):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def request(url, timeout, insecure=False, method="GET", headers=None):
    context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context), SameOriginRedirect()
    )
    supplied = {"User-Agent": f"Richtofen-PHP-Audit/{VERSION}", "Accept": "text/html,*/*;q=0.8"}
    supplied.update(headers or {})
    req = urllib.request.Request(url, headers=supplied, method=method)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers.items()), resp.geturl(), resp.read(65536), None
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()), url, exc.read(65536), None
    except (OSError, ValueError) as exc:
        return None, {}, url, b"", str(exc)


def scan(url, timeout, insecure=False, paths=None, delay=0, headers=None):
    paths = paths or []
    targets = [url]
    root = urllib.parse.urlsplit(url)
    base = urllib.parse.urlunsplit((root.scheme, root.netloc, "/", "", ""))
    for path in paths:
        path = path.strip()
        if not path.startswith("/") or path.startswith("//"):
            continue
        candidate = urllib.parse.urljoin(base, path)
        if candidate not in targets:
            targets.append(candidate)
    observations = []
    candidates = []
    php_signals = set()
    last_error = None
    for index, target in enumerate(targets):
        if index and delay:
            time.sleep(delay)
        status, response_headers, final_url, body, error = request(target, timeout, insecure, headers=headers)
        last_error = error or last_error
        observations.append({"url": target, "final_url": final_url, "status": status, "error": error})
        lowered = {k.lower(): v for k, v in response_headers.items()}
        for key in ("server", "x-powered-by", "x-php-version"):
            value = lowered.get(key, "")
            match = PATTERN.search(value)
            if match:
                candidates.append({"version": ".".join(match.groups()), "source": f"header:{key}", "endpoint": target})
            if "php" in value.lower():
                php_signals.add(f"header:{key}")
        if "phpsessid" in lowered.get("set-cookie", "").lower():
            php_signals.add("cookie:PHPSESSID")
        text = body.decode("utf-8", "replace")
        if "PHP Version" in text and ("phpinfo()" in text or "phpinfo" in text.lower()):
            match = re.search(r"PHP Version\s*(?:</?[^>]+>\s*)*(\d+\.\d+\.\d+)", text, re.I)
            if match:
                candidates.append({"version": match.group(1), "source": "phpinfo:body", "endpoint": target})
                php_signals.add("body:phpinfo")
    versions = sorted({c["version"] for c in candidates})
    version = versions[0] if len(versions) == 1 else None
    primary = observations[0]
    phpinfo_sources = [c for c in candidates if c["source"] == "phpinfo:body"]
    header_sources = [c for c in candidates if c["source"].startswith("header:")]
    if len(versions) > 1:
        confidence = "CONFLICT"
        source = "CONFLICTING_EVIDENCE"
        endpoint = None
    elif phpinfo_sources:
        confidence = "HIGH"
        source = phpinfo_sources[0]["source"]
        endpoint = phpinfo_sources[0]["endpoint"]
    elif header_sources:
        confidence = "MEDIUM"
        source = header_sources[0]["source"]
        endpoint = header_sources[0]["endpoint"]
    else:
        confidence = "NONE"
        source = None
        endpoint = None
    assessment = "CONFLICTING_EVIDENCE" if len(versions) > 1 else classify(version)
    cve_assessment = ("POTENTIALLY_AFFECTED" if assessment in ("BELOW_UPSTREAM_FIX", "LEGACY_BRANCH_REVIEW")
                      else "UPSTREAM_FIXED" if assessment == "UPSTREAM_FIXED_VERSION"
                      else "INCONCLUSIVE")
    return {
        "target": url, "final_url": primary["final_url"], "http_status": primary["status"],
        "php_version": version, "php_detected": bool(candidates or php_signals),
        "version_source": source, "evidence_endpoint": endpoint, "version_confidence": confidence,
        "php_signals": sorted(php_signals), "version_sources": candidates,
        "version_conflict": len(versions) > 1, "version_assessment": assessment,
        "patch_status": "UNKNOWN", "cve_status": "NOT_CONFIRMED", "cve_assessment": cve_assessment,
        "cve_ids": list(CVES),
        "exploitability": "NOT_TESTED", "observations": observations,
        "error": primary["error"],
    }


def local_scan(binary):
    try:
        p = subprocess.run([binary, "-r", "echo PHP_VERSION;"], capture_output=True, text=True, timeout=8, check=True)
        version = p.stdout.strip()
        return {"target": f"local:{binary}", "php_version": version,
                "version_assessment": classify(version), "version_source": "local:PHP_VERSION",
                "version_confidence": "HIGH", "cve_status": "NOT_CONFIRMED", "patch_status": "UNKNOWN",
                "cve_assessment": "POTENTIALLY_AFFECTED" if classify(version) in ("BELOW_UPSTREAM_FIX", "LEGACY_BRANCH_REVIEW") else "UPSTREAM_FIXED" if classify(version) == "UPSTREAM_FIXED_VERSION" else "INCONCLUSIVE",
                "cve_ids": list(CVES), "evidence_endpoint": None,
                "exploitability": "NOT_TESTED", "error": None}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"target": f"local:{binary}", "error": str(exc)}


def save(results, prefix):
    path = Path(prefix)
    path.parent.mkdir(parents=True, exist_ok=True)
    report = {"tool": "Richtofen PHP2Shell Detector", "version": VERSION, "author": AUTHOR,
              "scanned_at": datetime.now(timezone.utc).isoformat(), "cves": list(CVES),
              "disclaimer": "Remote evidence is non-exploitative. A version match does not prove RCE, and distro backports may invalidate upstream version comparisons.",
              "results": results}
    with open(str(path) + ".json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    keys = ["target", "http_status", "php_version", "version_source", "evidence_endpoint", "version_confidence", "version_assessment", "cve_assessment", "patch_status", "cve_status", "exploitability", "error"]
    with open(str(path) + ".csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Richtofen PHP2Shell CVE exposure detection for live targets")
    parser.add_argument("url", nargs="?", help="Single URL")
    parser.add_argument("-l", "-f", "--list", dest="targets", help="URL list file")
    parser.add_argument("--local", nargs="?", const="php", metavar="PHP_BIN", help="Check local PHP executable")
    parser.add_argument("-t", "--threads", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=8)
    parser.add_argument("--insecure", action="store_true", help="Disable TLS validation")
    parser.add_argument("--path", action="append", default=[], help="Additional same-origin path (repeatable)")
    parser.add_argument("--phpinfo-paths", action="store_true", help="Check common phpinfo paths")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests to one target")
    parser.add_argument("-H", "--header", action="append", default=[], help="Custom request header (repeatable)")
    parser.add_argument("-o", "--output", default="php_results")
    parser.add_argument("--no-banner", action="store_true")
    args = parser.parse_args(argv)
    if args.threads < 1 or args.threads > 5 or args.timeout <= 0 or args.delay < 0:
        parser.error("threads must be 1-5 and timeout must be positive")
    if not args.url and not args.targets and not args.local:
        parser.error("provide a URL, -l targets.txt, or --local")
    if not args.no_banner:
        print("\n" + "=" * 48)
        print("  RICHTOFEN PHP2SHELL DETECTOR")
        print(f"  v{VERSION} | Author: {AUTHOR}")
        print("=" * 48 + "\n")
    headers = {}
    for entry in args.header:
        if ":" not in entry:
            parser.error("headers must use Name: Value")
        key, value = entry.split(":", 1)
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key) or "\r" in value or "\n" in value:
            parser.error("invalid header")
        if key.lower() in ("host", "content-length", "transfer-encoding"):
            parser.error("overriding transport headers is unsupported")
        headers[key] = value.strip()
    paths = list(args.path)
    if args.phpinfo_paths:
        paths += ["/phpinfo.php", "/info.php", "/php_info.php"]
    raw = ([args.url] if args.url else [])
    if args.targets:
        try:
            raw += Path(args.targets).read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            parser.error(str(exc))
    urls, seen, results = [], set(), []
    for item in raw:
        try:
            url = normalize(item)
            if url and url not in seen:
                urls.append(url)
                seen.add(url)
        except ValueError as exc:
            results.append({"target": item.strip(), "error": str(exc), "version_assessment": "ERROR"})
    if args.local:
        results.append(local_scan(args.local))
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan, url, args.timeout, args.insecure, paths, args.delay, headers): url for url in urls}
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
            except Exception as exc:
                result = {"target": futures[future], "error": str(exc), "version_assessment": "ERROR"}
            results.append(result)
            print(f"[{result.get('http_status') or '-'}] {result['target']}")
            print(f"      PHP:        {result.get('php_version') or '?'}")
            print(f"      Source:     {result.get('version_source') or 'UNKNOWN'}")
            print(f"      Endpoint:   {result.get('evidence_endpoint') or 'UNKNOWN'}")
            print(f"      Confidence: {result.get('version_confidence') or 'NONE'}")
            print(f"      Status:     {result.get('version_assessment') or 'ERROR'}")
            print(f"      PHP2Shell:  {result.get('cve_assessment') or 'INCONCLUSIVE'}")
            print(f"      Exploit:    {result.get('cve_status') or 'NOT_CONFIRMED'}")
            if result.get("error"):
                print(f"      Error:      {result['error']}")
    results.sort(key=lambda x: x["target"])
    save(results, args.output)
    print("\n" + "=" * 48)
    print("  SCAN SUMMARY")
    print("=" * 48)
    print(f"  Total targets:          {len(results)}")
    print(f"  PHP version identified: {sum(bool(r.get('php_version')) for r in results)}")
    print(f"  PHP detected (no ver):  {sum(bool(r.get('php_detected')) and not r.get('php_version') for r in results)}")
    print(f"  PHP not confirmed:      {sum(not r.get('php_detected') and not r.get('php_version') for r in results)}")
    print(f"  Potentially affected:   {sum(r.get('cve_assessment') == 'POTENTIALLY_AFFECTED' for r in results)}")
    print(f"  Legacy branches:        {sum(r.get('version_assessment') == 'LEGACY_BRANCH_REVIEW' for r in results)}")
    print(f"  Below upstream fix:     {sum(r.get('version_assessment') == 'BELOW_UPSTREAM_FIX' for r in results)}")
    print(f"  Upstream fixed version: {sum(r.get('version_assessment') == 'UPSTREAM_FIXED_VERSION' for r in results)}")
    print(f"  Unknown/conflicting:    {sum(r.get('version_assessment') in ('UNKNOWN', 'CONFLICTING_EVIDENCE', 'NOT_IN_VERSION_TABLE') for r in results)}")
    print(f"  Request/input errors:   {sum(bool(r.get('error')) for r in results)}")
    print(f"  Exploitation confirmed: 0 (not tested)")
    print("=" * 48)
    print(f"\nSaved: {args.output}.json, {args.output}.csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
