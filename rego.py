#!/usr/bin/env python3
"""
gork.py - Automated Google Dorking for Bug Bounty Reconnaissance

Generates and executes targeted dork queries against a target domain,
following the "forgotten assets" methodology:
  - site:*.target.com -www          -> non-primary subdomains
  - Sensitive file extensions       -> .env, .sql, .bak, .log, .txt, .xml, .json
  - Directory listings / exposed panels
  - Credentials / tokens / API keys in indexed files

Backends:
  - serpapi     : SerpAPI (needs SERPAPI_KEY env var or --key)
  - duckduckgo  : DuckDuckGo HTML scraping (no key, rate-limited)
  - manual      : just print browser-ready Google URLs (default, safest)

Usage:
  python3 gork.py -d example.com
  python3 gork.py -d example.com -b duckduckgo -o results.json --delay 8
  python3 gork.py -d example.com --custom 'site:*.example.com inurl:admin'
  export SERPAPI_KEY=xxxx && python3 gork.py -d example.com -b serpapi
"""

import argparse
import json
import os
import random
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    sys.exit("[!] 'requests' is required: pip install requests")

try:
    from bs4 import BeautifulSoup
except ImportError:
    sys.exit("[!] 'beautifulsoup4' is required: pip install beautifulsoup4")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
]


# --------------------------------------------------------------------------
# Dork template generation
# --------------------------------------------------------------------------

@dataclass
class Dork:
    category: str
    query: str

    def google_url(self) -> str:
        return "https://www.google.com/search?q=" + urllib.parse.quote(self.query)


def build_dorks(domain: str) -> list[Dork]:
    """Generate the dork arsenal for a target domain."""
    wild = f"site:*.{domain}"          # catches subdomains AND nested paths
    root = f"site:{domain}"
    dorks: list[Dork] = []

    # --- 1. Forgotten / non-primary assets (the core technique) ---
    dorks += [
        Dork("forgotten_assets", f"{wild} -www -www.{domain}"),
        Dork("forgotten_assets", f'{root} -www -inurl:(www) -inurl:(login|signup|blog|about|contact|privacy|terms)'),
        Dork("forgotten_assets", f'{wild} -inurl:(www | blog | careers | support)'),
        Dork("subdomains_indexed", f"{wild} -inurl:https://www.{domain}"),
    ]

    # --- 2. Sensitive file extensions ---
    for ext in ("env", "sql", "bak", "log", "txt", "xml", "json", "conf",
                "config", "ini", "yml", "yaml", "old", "swp", "csv", "pem", "key"):
        dorks.append(Dork("sensitive_files", f'{root} (ext:{ext} OR filetype:{ext})'))

    # --- 3. Directory listings & backup artifacts ---
    dorks += [
        Dork("dir_listing", f'{root} intitle:"index of"'),
        Dork("dir_listing", f'{root} intitle:"index of" "parent directory"'),
        Dork("backups", f'{root} (inurl:backup | inurl:bak | inurl:dump | inurl:old)'),
        Dork("backups", f'{root} (ext:sql OR ext:bak OR ext:tar OR ext:zip OR ext:7z OR ext:rar)'),
    ]

    # --- 4. Exposed admin panels / dev endpoints ---
    dorks += [
        Dork("admin_panels", f'{root} (inurl:admin | inurl:administrator | inurl:manage | inurl:panel | inurl:dashboard)'),
        Dork("admin_panels", f'{root} intitle:"admin" OR intitle:"login" OR intitle:"dashboard"'),
        Dork("dev_staging", f'{root} (inurl:dev | inurl:staging | inurl:test | inurl:uat | inurl:preprod | inurl:beta)'),
        Dork("git_svn", f'{root} (inurl:.git | inurl:.svn | inurl:.htaccess | inurl:.DS_Store)'),
    ]

    # --- 5. Credentials / secrets / API docs ---
    dorks += [
        Dork("secrets", f'{root} (password | passwd | pwd | secret | token | api_key | apikey | "api key")'),
        Dork("secrets", f'{root} ("jdbc:" | "mysql://" | "postgres://" | "mongodb://" | "ftp://")'),
        Dork("secrets", f'{root} ("-----BEGIN RSA PRIVATE KEY-----" OR "-----BEGIN PRIVATE KEY-----")'),
        Dork("api_docs", f'{root} (inurl:swagger | inurl:api-docs | inurl:openapi | inurl:graphql | intitle:"swagger")'),
        Dork("api_docs", f'{root} (ext:openapi OR ext:swagger OR "openapi.json" OR "swagger.json")'),
    ]

    # --- 6. Cloud storage & error pages leaking stack info ---
    dorks += [
        Dork("cloud", f'{root} (s3.amazonaws.com | storage.googleapis.com | blob.core.windows.net)'),
        Dork("cloud", f'{root} ("cloudfront" | "cloudflare" | "azurewebsites" | "herokuapp")'),
        Dork("errors", f'{root} ("fatal error" | "sql syntax" | "warning: " | "stack trace" | "exception")'),
        Dork("tech_stack", f'{root} (ext:aspx OR ext:asp OR ext:ashx OR ext:asmx)'),   # ASPX-family
        Dork("tech_stack", f'{root} (ext:php | ext:jsp | ext:do | ext:action)'),
    ]

    return dorks


# --------------------------------------------------------------------------
# Search backends
# --------------------------------------------------------------------------

def fetch(session: requests.Session, url: str, delay: float) -> requests.Response:
    session.headers.update({"User-Agent": random.choice(USER_AGENTS)})
    time.sleep(delay + random.uniform(0, delay * 0.5))  # jittered rate limit
    return session.get(url, timeout=25)


def search_serpapi(session, query: str, key: str, delay: float) -> list[str]:
    resp = session.get(
        "https://serpapi.com/search",
        params={"q": query, "api_key": key, "num": 100},
        headers={"User-Agent": random.choice(USER_AGENTS)},
        timeout=30,
    )
    time.sleep(delay + random.uniform(0, delay * 0.5))
    if resp.status_code != 200:
        print(f"    [!] SerpAPI HTTP {resp.status_code}", file=sys.stderr)
        return []
    data = resp.json()
    urls = [item.get("link") for item in data.get("organic_results", []) if item.get("link")]
    return urls


def search_duckduckgo(session, query: str, delay: float) -> list[str]:
    resp = fetch(session, "https://html.duckduckgo.com/html/?q=" + urllib.parse.quote(query), delay)
    if resp.status_code != 200:
        print(f"    [!] DDG HTTP {resp.status_code}", file=sys.stderr)
        return []
    soup = BeautifulSoup(resp.text, "html.parser")
    urls = []
    for a in soup.select("a.result__a"):
        href = a.get("href", "")
        # DDG wraps URLs: /l/?uddg=<urlencoded>
        if "uddg=" in href:
            href = urllib.parse.unquote(href.split("uddg=")[1].split("&")[0])
        if href.startswith("http"):
            urls.append(href)
    return urls


# --------------------------------------------------------------------------
# Result processing / cross-reference-ready output
# --------------------------------------------------------------------------

SUBDOMAIN_RE = re.compile(r"https?://([^/:?#]+)")


def extract_host(url: str) -> str:
    m = SUBDOMAIN_RE.match(url)
    return m.group(1).lower() if m else ""


def classify(urls: list[str], domain: str) -> dict:
    """Bucket results so they can be cross-referenced with wayback/subfinder data later."""
    out = {"unique_urls": [], "hosts": {}, "file_extensions": {}}
    seen = set()
    for u in urls:
        if u in seen:
            continue
        seen.add(u)
        out["unique_urls"].append(u)
        host = extract_host(u)
        if host and (host == domain or host.endswith("." + domain)):
            out["hosts"].setdefault(host, []).append(u)
        ext = ""
        path = urllib.parse.urlparse(u).path
        filename = path.rsplit("/", 1)[-1]
        if "." in filename:
            ext = filename.rsplit(".", 1)[-1].lower()[:8]
        if ext:
            out["file_extensions"].setdefault(ext, []).append(u)
    return out


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="Automated Google Dorking for recon")
    p.add_argument("-d", "--domain", required=True, help="target domain, e.g. example.com")
    p.add_argument("-b", "--backend", choices=["manual", "duckduckgo", "serpapi"], default="manual")
    p.add_argument("-k", "--key", default=os.environ.get("SERPAPI_KEY"), help="SerpAPI key (or SERPAPI_KEY env)")
    p.add_argument("--custom", action="append", default=[], help="extra raw dork queries (repeatable)")
    p.add_argument("--delay", type=float, default=6.0, help="min seconds between queries (default 6)")
    p.add_argument("-o", "--output", default=f"dorks_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    args = p.parse_args()

    dorks = build_dorks(args.domain)
    for q in args.custom:
        dorks.append(Dork("custom", q))

    print(f"[*] Target : {args.domain}")
    print(f"[*] Dorks  : {len(dorks)}")
    print(f"[*] Backend: {args.backend}\n")

    session = requests.Session()
    all_results = {}

    if args.backend == "manual":
        print("[*] Manual mode - open these in your browser (or feed to a search API):\n")
        for d in dorks:
            print(f"  [{d.category}] {d.query}")
            print(f"      {d.google_url()}\n")
        with open(args.output, "w") as f:
            json.dump([{"category": d.category, "query": d.query, "url": d.google_url()} for d in dorks], f, indent=2)
        print(f"[+] Dork list saved -> {args.output}")
        return

    for i, d in enumerate(dorks, 1):
        print(f"[{i}/{len(dorks)}] ({d.category}) {d.query}")
        try:
            if args.backend == "serpapi":
                if not args.key:
                    sys.exit("[!] SerpAPI backend requires --key or SERPAPI_KEY")
                urls = search_serpapi(session, d.query, args.key, args.delay)
            else:
                urls = search_duckduckgo(session, d.query, args.delay)
        except requests.RequestException as e:
            print(f"    [!] Request failed: {e}")
            urls = []

        print(f"    -> {len(urls)} results")
        all_results[d.query] = {"category": d.category, "urls": urls}

    flat = [u for r in all_results.values() for u in r["urls"]]
    summary = {
        "target": args.domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "queries": all_results,
        "summary": classify(flat, args.domain),
    }
    with open(args.output, "w") as f:
        json.dump(summary, f, indent=2)

    hosts = summary["summary"]["hosts"]
    print(f"\n[+] {len(flat)} total results | {len(hosts)} unique hosts under *.{args.domain}")
    for h in sorted(hosts):
        print(f"    {h} ({len(hosts[h])} urls)")
    print(f"[+] Saved -> {args.output}  (keep this for cross-referencing with waymore/subfinder data)")


if __name__ == "__main__":
    main()
