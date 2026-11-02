#!/usr/bin/env python3
"""Local watcher for the Absa Youth Entrepreneurship Fund WhatsApp scam.

Run on your own machine (the cloud sandbox proxy blocks metaink.xyz):
    pip install requests
    python watch.py

Rules: plain GET only, one per URL, never follows redirects, never submits
forms, never requests otieu.com or other metaink.xyz slugs. URLs are printed
defanged. Known sites are kept in known_sites.json next to this script.
"""
import json, re, sys, time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import requests

UA = ("Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
      "Chrome/124 Mobile Safari/537.36")
REDIRECTOR = "https://metaink.xyz/ABSA-Youth-Fund"
STATE = Path(__file__).with_name("known_sites.json")

QUERIES = [
    'page.title:"ABSA YOUTH ENTREPRENEURSHIP FUND"',
    "hash:224479bab10c9d9a1c1dd77586bbdc3c18f73bbedefc855c7e952dda1832fa2a",
    "hash:e563dd5701d93937dcb6160ac5c469ce92e7c03070c470b27631cd86de2e1a94",
    "hash:76df772a92212db9a4ec17e9a84d326fe13f6e3415377c1536c2f88d9339c3b1",
    # regex domain queries are 403 for anonymous urlscan users; try anyway
    r"page.domain:/.*absa.*\.(blogspot\.com|github\.io|pages\.dev|netlify\.app|vercel\.app|web\.app)/",
]
OPERATOR = ["otieu.com/4/10077877", "sc_online_i(1739582",
            "metaink.xyz/ABSA-Youth-Fund"]
TEMPLATE = ['history.pushState(history.length+1, "message", "#"+Math.random())',
            "Posts are not calculated", "whatsapp://send?text=",
            "widget.supercounters.com"]


def defang(u):
    return u.replace("http", "hxxp", 1).replace(".", "[.]")


def get(url, **kw):
    # One plain GET, no redirect following.
    return requests.get(url, headers={"User-Agent": UA}, timeout=25,
                        allow_redirects=False, **kw)


def main():
    known = json.loads(STATE.read_text()) if STATE.exists() else {}
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    candidates = {}
    report = []
    rfile = Path(__file__).with_name("redirector.json")
    last_host = json.loads(rfile.read_text()).get("host") if rfile.exists() else None

    # 1. Redirector (state = host, or "unreachable"/"no-redirect" so a change is reported)
    try:
        r = get(REDIRECTOR)
        loc = r.headers.get("Location", "")
        target = loc.split("#")[0]
        print(f"Redirector: {r.status_code} -> {defang(loc) or '(none)'}")
        cur = urlsplit(target).hostname if target else f"no-redirect-{r.status_code}"
        if target:
            candidates[target] = "redirector"
    except requests.RequestException as e:
        print("Redirector: ERROR", e)
        cur = "unreachable-dns" if "NameResolution" in str(e) else "unreachable"
    if cur != last_host:
        report.append(f"**Redirector changed:** was {last_host}, now {cur}"
                      + (f" ({defang(target)})" if cur and "." in cur and target else ""))
        rfile.write_text(json.dumps({"host": cur}))

    # 2. urlscan
    for q in QUERIES:
        try:
            r = requests.get("https://urlscan.io/api/v1/search/",
                             params={"q": q, "size": 100},
                             headers={"User-Agent": UA}, timeout=30)
            if r.status_code == 429:
                print("urlscan 429 (rate limited):", q[:50])
            elif r.status_code != 200:
                print(f"urlscan {r.status_code}:", q[:50])
            else:
                for res in r.json().get("results", []):
                    u = res["page"].get("url", "").split("#")[0]
                    if u and u not in known:
                        candidates.setdefault(u, "urlscan")
        except requests.RequestException as e:
            print("urlscan ERROR", e)
        time.sleep(2)

    # 3/4. Fingerprint new candidates + recheck known sites
    to_check = set(candidates) | {u for u, v in known.items()
                                  if v.get("status") not in ("404", "gone")}
    for u in sorted(to_check):
        if urlsplit(u).hostname and urlsplit(u).hostname.endswith("otieu.com"):
            continue
        try:
            r = get(u)
            if r.status_code in (301, 302) and "blogspot." in r.headers.get("Location", ""):
                r = get(r.headers["Location"])  # blogspot country/mobile hop
            html = r.text if r.status_code == 200 else ""
            op = [m for m in OPERATOR if m in html]
            tp = [m for m in TEMPLATE if m in html]
            if "Blog not found" in html:
                grade, status = "gone", "gone"
            else:
                status = str(r.status_code)
                grade = ("CONFIRMED" if op else "SAME TEMPLATE" if tp
                         else "UNRELATED" if r.status_code == 200 else "n/a")
            exfil = bool(re.search(r"<form[^>]+action=|fetch\(|XMLHttpRequest", html))
            print(f"{'NEW ' if u not in known else ''}{defang(u)}  "
                  f"{status}  {grade}  op={op} tpl={len(tp)}"
                  f"{'  !! form/fetch present, review for data exfil' if exfil and grade != 'UNRELATED' else ''}")
            prev = known.get(u)
            if prev is None and grade in ("CONFIRMED", "SAME TEMPLATE"):
                report.append(f"**NEW {grade}:** {defang(u)} (HTTP {status}) operator={op} template_markers={len(tp)}"
                              f"{' FORM/FETCH PRESENT - possible data exfil' if exfil else ''}")
            elif prev is not None and prev.get("status") != status:
                report.append(f"Status change: {defang(u)} {prev.get('status')} -> {status}")
            known[u] = {"status": status, "grade": grade, "last_checked": today,
                        "operator_markers": op}
        except requests.RequestException as e:
            print(f"{defang(u)}  ERROR {e}")
        time.sleep(2)

    STATE.write_text(json.dumps(known, indent=2))
    rp = Path(__file__).with_name("report.md")
    if report:
        rp.write_text("\n".join("- " + line for line in report) + "\n")
    elif rp.exists():
        rp.unlink()
    print(f"\nSaved {len(known)} sites to {STATE.name}")


if __name__ == "__main__":
    sys.exit(main())
