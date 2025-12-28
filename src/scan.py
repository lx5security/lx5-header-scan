#!/usr/bin/env python3
"""
LX5 Header Scan
---------------

Educational tool to inspect common HTTP security headers.

Intent:
- Defensive security learning
- Awareness of web hardening practices
- No exploitation, no misuse

Only scan systems you own or have permission to test.
"""

from __future__ import annotations

import sys
import argparse
from datetime import datetime, timezone
from typing import Dict, Tuple, Optional

import requests


SECURITY_HEADERS: Dict[str, str] = {
    "Content-Security-Policy": "Helps prevent XSS and data injection attacks",
    "X-Frame-Options": "Protects against clickjacking",
    "X-Content-Type-Options": "Prevents MIME type sniffing",
    "Referrer-Policy": "Controls referrer information sent by the browser",
    "Strict-Transport-Security": "Enforces HTTPS connections (HSTS)",
    "Permissions-Policy": "Restricts access to browser features",
    # Optional / legacy-ish but still seen:
    "Cross-Origin-Opener-Policy": "Helps isolate browsing contexts (COOP)",
    "Cross-Origin-Resource-Policy": "Controls who can load resources (CORP)",
    "Cross-Origin-Embedder-Policy": "Requires cross-origin isolation (COEP)",
}


def normalize_url(url: str, force_https: bool) -> str:
    url = url.strip()
    if not url:
        raise ValueError("Empty URL")
    if url.startswith("http://") or url.startswith("https://"):
        if force_https and url.startswith("http://"):
            url = "https://" + url[len("http://") :]
        return url
    # If user passed a naked domain like example.com
    return ("https://" if force_https else "https://") + url


def fetch(url: str, timeout: int, allow_redirects: bool) -> Tuple[requests.Response, str]:
    headers = {
        "User-Agent": "LX5-Header-Scan/1.0 (+https://www.lx5security.com/)",
        "Accept": "*/*",
    }
    resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=allow_redirects)
    final_url = resp.url
    return resp, final_url


def analyze_headers(resp: requests.Response) -> Tuple[Dict[str, str], Dict[str, str]]:
    present: Dict[str, str] = {}
    missing: Dict[str, str] = {}

    # requests makes headers case-insensitive, but we'll access by exact names
    for h, desc in SECURITY_HEADERS.items():
        if h in resp.headers:
            present[h] = resp.headers.get(h, "")
        else:
            missing[h] = desc

    return present, missing


def print_report(target: str, final_url: str, status_code: int, present: Dict[str, str], missing: Dict[str, str]) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

    print("\n" + "=" * 72)
    print("LX5 Header Scan")
    print("=" * 72)
    print(f"Time (UTC):     {now}")
    print(f"Target:         {target}")
    print(f"Final URL:      {final_url}")
    print(f"HTTP Status:    {status_code}")
    print("-" * 72)

    if present:
        print("\n[+] Present security headers:")
        for k in sorted(present.keys()):
            v = present[k].strip()
            # Keep it readable
            if len(v) > 180:
                v = v[:180] + "…"
            print(f"  - {k}: {v}")
    else:
        print("\n[!] No tracked security headers were detected.")

    if missing:
        print("\n[-] Missing (recommended) headers:")
        for k in sorted(missing.keys()):
            print(f"  - {k}: {missing[k]}")
    else:
        print("\n[+] All tracked headers detected. Nice.")

    print("\nNote: Header presence alone doesn't guarantee security.")
    print("=" * 72 + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="lx5-header-scan",
        description="Inspect common HTTP security headers (defensive/educational).",
    )
    parser.add_argument("url", help="URL or domain to scan (e.g., https://example.com or example.com)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--no-redirects", action="store_true", help="Do not follow redirects")
    parser.add_argument("--http-ok", action="store_true", help="Allow http:// if provided (default forces https)")
    args = parser.parse_args()

    try:
        target = normalize_url(args.url, force_https=not args.http_ok)
    except ValueError as e:
        print(f"[!] Invalid URL: {e}")
        return 2

    try:
        resp, final_url = fetch(target, timeout=args.timeout, allow_redirects=not args.no_redirects)
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed: {e}")
        return 1

    present, missing = analyze_headers(resp)
    print_report(target=target, final_url=final_url, status_code=resp.status_code, present=present, missing=missing)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
