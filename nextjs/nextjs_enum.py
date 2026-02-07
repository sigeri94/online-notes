#!/usr/bin/env python3
"""
next_enum.py
Focused enumeration for Next.js + React apps (client-side artifacts).

Features:
 - Fetch / parse __NEXT_DATA__ (if present) to extract buildId, assetPrefix, runtimeConfig, page, etc.
 - Enumerate /_next/ static paths (chunks, static, data) and attempt to fetch framework-*.js to find version strings.
 - Check for exposed source maps (*.map) for bundles (may reveal source & versions).
 - Probe /_next/data/{buildId}/*.json for page data.
 - Probe common Next.js/React-related files: next.config.js, package.json, .env, public/ files.
 - Check robots.txt, sitemap.xml.
 - Heuristics for common API routes (/api/, /api/auth, /api/upload, /api/hello).
 - Produce JSON output and human readable summary.
"""
import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

# --- Config
COMMON_API_PATHS = [
    "/api/", "/api/auth", "/api/auth/login", "/api/auth/me",
    "/api/upload", "/api/upload/esign", "/api/upload/document",
    "/api/hello", "/api/graphql"
]

COMMON_PROBES = [
    "next.config.js", "package.json", ".env", "server.js",
    "yarn.lock", "package-lock.json", "public/robots.txt", "robots.txt", "sitemap.xml"
]

HEADERS = {
    "User-Agent": "next-enum/1.0 (+https://example.com)"
}

# regex
NEXT_DATA_RE = re.compile(r'__NEXT_DATA__"\s*>\s*(\{.*\})\s*<\/script>', re.DOTALL)
VERSION_RE = re.compile(r't\.version\s*=\s*["\']([\d\.abrc]+)["\']', re.IGNORECASE)
FRAMEWORK_BUNDLE_RE = re.compile(r'framework-[0-9a-f]+\.js')
CHUNK_BUNDLE_RE = re.compile(r'(main|framework|webpack|commons)-[0-9a-f]+\.js')

# helpers
def norm_base(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url.rstrip("/")

def safe_get(url, timeout=10, allow_redirects=True):
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=allow_redirects)
        return r
    except Exception as e:
        return None

def fetch_next_data_from_html(text):
    """Try many ways to extract __NEXT_DATA__ JSON from HTML."""
    # Try DOM script id search via BeautifulSoup first
    try:
        soup = BeautifulSoup(text, "html.parser")
        el = soup.find("script", {"id": "__NEXT_DATA__"})
        if el and el.string:
            return json.loads(el.string)
    except Exception:
        pass
    # fallback regex
    m = NEXT_DATA_RE.search(text)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    return None

def discover_buildid_and_assetprefix(next_data):
    out = {}
    if not next_data:
        return out
    for k in ("buildId", "assetPrefix", "runtimeConfig", "page", "query", "isFallback", "dynamicIds"):
        if k in next_data:
            out[k] = next_data[k]
    return out

def probe_common_files(base_url):
    findings = {}
    for p in COMMON_PROBES:
        url = urljoin(base_url + "/", p)
        r = safe_get(url)
        if r and r.status_code < 400:
            findings[p] = {"status": r.status_code, "url": r.url, "excerpt": (r.text[:1000] if r.text else "")}
        else:
            findings[p] = {"status": r.status_code if r else None}
    return findings

def list_next_static(base_url):
    """Try to list likely /_next/static and chunk files by crawling HTML and probing known paths."""
    found = {"assets": set(), "framework_candidates": set(), "map_candidates": set()}
    # fetch homepage HTML to find script tags
    r = safe_get(base_url)
    if not r:
        return found
    soup = BeautifulSoup(r.text, "html.parser")
    for script in soup.find_all("script", src=True):
        src = script["src"]
        if "/_next/" in src:
            u = urljoin(base_url + "/", src)
            found["assets"].add(u)
            # detect framework-* js
            if FRAMEWORK_BUNDLE_RE.search(src):
                found["framework_candidates"].add(u)
            # also detect .map urls (some bundles contain //# sourceMappingURL=foo.js.map)
    # scan inline for sourceMappingURL comments
    for m in re.finditer(r"sourceMappingURL=([^\s'\";]+)", r.text):
        map_rel = m.group(1)
        map_url = urljoin(base_url + "/", map_rel)
        found["map_candidates"].add(map_url)
    # also try naive index for /_next/static/chunks/
    base_chunks = urljoin(base_url + "/", "/_next/static/chunks/")
    # Do a few guesses for common chunk names if not found
    guesses = [
        "/_next/static/chunks/framework-*.js",
        "/_next/static/chunks/main-*.js",
        "/_next/static/chunks/commons-*.js"
    ]
    # try to fetch chunk listing via known pattern (many servers won't list dir)
    for g in guesses:
        # we can't glob on HTTP; instead try to look up by reading HTML assets we already found
        pass
    return {k: list(v) for k, v in found.items()}

def fetch_and_search_versions(urls):
    results = []
    for u in urls:
        r = safe_get(u)
        if not r:
            results.append({"url": u, "status": None, "versions": []})
            continue
        text = r.text or ""
        versions = VERSION_RE.findall(text)
        # also try to search for "Next.js" or "next" or "Next" textual hints
        next_hints = []
        if "Next.js" in text or "next" in text.lower():
            next_hints.append("maybe-next-hint")
        results.append({"url": u, "status": r.status_code, "versions": list(set(versions)), "hint_count": len(next_hints)})
    return results

def try_fetch_sourcemap_for(js_url):
    """Given a JS bundle URL, try to fetch its .map by appending .map or reading sourceMappingURL comment."""
    # direct .map
    map_url = js_url + ".map"
    r = safe_get(map_url)
    if r and r.status_code < 400:
        return {"map_url": map_url, "status": r.status_code, "size": len(r.content)}
    # fetch js and parse sourceMappingURL
    rjs = safe_get(js_url)
    if rjs and rjs.status_code < 400:
        m = re.search(r"\/\/# sourceMappingURL=(.+)$", rjs.text, re.MULTILINE)
        if m:
            rel = m.group(1).strip()
            full = urljoin(js_url, rel)
            rm = safe_get(full)
            if rm and rm.status_code < 400:
                return {"map_url": full, "status": rm.status_code, "size": len(rm.content)}
    return None

def probe_next_data_endpoint(base_url, build_id):
    """Try to hit /_next/data/{buildId}/ and typical JSON per page if __NEXT_DATA__ had page."""
    out = {}
    if not build_id:
        return out
    base = urljoin(base_url + "/", f"/_next/data/{build_id}/")
    # try root page index.json
    candidates = ["index.json", "index.html", "index.js"]
    for c in candidates:
        url = urljoin(base, c)
        r = safe_get(url)
        out[c] = {"status": r.status_code if r else None, "url": r.url if r else None}
    return out

def probe_api_paths(base_url):
    found = {}
    for p in COMMON_API_PATHS:
        url = urljoin(base_url + "/", p)
        r = safe_get(url)
        found[p] = {"status": r.status_code if r else None, "url": r.url if r else None}
    return found

def run_all(target, workers=8, probe_maps=True):
    target = norm_base(target)
    summary = {"target": target, "next_data": None, "build": {}, "assets": [], "framework_checks": [], "map_checks": [], "common_files": {}, "api_probes": {}}

    # fetch homepage
    r = safe_get(target)
    if not r:
        print("[!] Could not fetch target.")
        return summary

    # parse __NEXT_DATA__
    nd = fetch_next_data_from_html(r.text)
    summary["next_data"] = nd
    if nd:
        summary["build"] = discover_buildid_and_assetprefix(nd)
    # probe common files
    summary["common_files"] = probe_common_files(target)
    # list next static assets heuristically
    assets = list_next_static(target)
    summary["assets"] = assets

    # collect candidate framework/js bundles from assets
    candidates = set(assets.get("assets", [])) | set(assets.get("framework_candidates", []))
    # also scan HTML for /_next/static/ paths
    for m in re.finditer(r'(/_next/[^\s"\'<>]+)', r.text):
        candidates.add(urljoin(target + "/", m.group(1)))

    # fetch candidate js and search for versions
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(fetch_and_search_versions, [u]): u for u in list(candidates)[:50]}
        for f in as_completed(futures):
            try:
                res = f.result()
                summary["framework_checks"].extend(res)
            except Exception as e:
                pass

    # try fetch sourcemaps for top candidate scripts if requested
    if probe_maps:
        js_urls = [i["url"] for i in summary["framework_checks"] if i.get("status") and i["status"] < 400]
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(try_fetch_sourcemap_for, u): u for u in js_urls[:20]}
            for f in as_completed(futures):
                try:
                    rmap = f.result()
                    if rmap:
                        summary["map_checks"].append(rmap)
                except Exception:
                    pass

    # probe next data endpoint
    build_id = summary["build"].get("buildId")
    summary["next_data_endpoints"] = probe_next_data_endpoint(target, build_id)

    # probe API routes
    summary["api_probes"] = probe_api_paths(target)

    return summary

def main():
    parser = argparse.ArgumentParser(description="Next.js focused enumeration (authorized use only).")
    parser.add_argument("target", help="Target domain or URL (e.g. example.com or https://example.com)")
    parser.add_argument("--no-maps", action="store_true", help="Do not attempt to fetch source maps")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--json-out", help="Write JSON output to file")
    args = parser.parse_args()

    print("[*] Starting Next.js enumeration for:", args.target)
    summary = run_all(args.target, workers=args.workers, probe_maps=not args.no_maps)

    # pretty print summary
    print("\n=== Summary ===")
    print("Target:", summary["target"])
    print("Detected __NEXT_DATA__:", "Yes" if summary["next_data"] else "No")
    if summary["build"]:
        print("Build info:", json.dumps(summary["build"], indent=2))
    print("\nCommon files (status):")
    for k, v in summary["common_files"].items():
        print(f"  {k}: {v.get('status')} {v.get('url','') if v.get('url') else ''}")
    print("\nFramework checks (found versions):")
    for c in summary["framework_checks"]:
        if c.get("versions"):
            print(f"  {c['url']} -> versions: {c['versions']}")
    if summary["map_checks"]:
        print("\nFound reachable source maps (may contain sources):")
        for m in summary["map_checks"]:
            print("  ", m.get("map_url"), "size:", m.get("size"))

    if args.json_out:
        try:
            with open(args.json_out, "w", encoding="utf-8") as fh:
                json.dump(summary, fh, indent=2)
            print("\n[+] JSON output written to", args.json_out)
        except Exception as e:
            print("[!] Failed to write JSON:", e)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted by user.")
        sys.exit(1)
