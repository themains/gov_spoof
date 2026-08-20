"""Collection adapter: does the institution still control the domain?

The frame takes its domains from Wikidata `P856`, and nothing validated that a
`P856` value still points at the institution -- or ever did. Three domains in
the 2026-08-20 sweep no longer belong to the body they are filed under:

    apn-dz.org                     Algeria, legislature
                                   -> a private detective agency in Ichikawa, Japan
    editorialshindi.in             India, head of state
                                   -> a Bangladeshi online casino
    asambleanacionalvenezuela.org  Venezuela, legislature
                                   -> an Indonesian gambling site

apn-dz.org is the one that shows why this matters. It publishes a valid DMARC
record, so the posture table scored it PROTECTED and the finding read "Algeria's
parliament blocks forged mail". The detective agency blocks forged mail. The
parliament lost the domain.

That is not a smaller version of the finding, it is a different fact, and one
that runs the opposite way: an institution whose domain was re-registered by a
stranger has a worse problem than one that can be spoofed. Two more entries are
wrong rather than lost -- pakistanpressfoundation.org is an NGO standing in for
Pakistan's Supreme Court, tsjlegitimo.org is Venezuela's tribunal in exile --
and India's President carries both the real presidentofindia.gov.in and an SEO
article URL, because `P856` accepts whatever anyone typed.

WHAT THIS DOES, AND WHAT IT DELIBERATELY DOES NOT DO. One unauthenticated GET of
the homepage each institution publishes, recording status, redirect target and
title. That is the same single request a browser makes when a person visits the
page. It does not scan, does not enumerate paths, does not touch mail
infrastructure and does not authenticate. The project's disclosure section is
written to match, because a promise that no request is ever made would now be
false.

IT FLAGS; IT DOES NOT EXCLUDE. Keyword classification of a page title is far too
blunt to retire a country's parliament from a dataset. The first version of this
matched "judi" for gambling and hit "Poder Judicial" and "Judiciary of The
Gambia" -- two supreme courts, correctly filed, nearly dropped by a substring.
So the flag opens a question and `data/domain_control_review.csv` answers it,
by hand, with the evidence and the reason recorded next to each verdict.

FROZEN. Listed in FROZEN_COLLECTORS; never runs in a build.

Usage:  python scripts/collect/site_content.py
"""

import os
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from urllib.parse import urlparse

import pandas as pd
import requests

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
FRAME = os.path.join(REPO, "data", "institution_domains.csv")
OUT = os.path.join(REPO, "data", "institution_site_content.csv")

# Identifies the project and gives an operator somewhere to complain to. A
# research crawler that hides behind a browser string is the kind that gets
# whole institutions blocking a university's netblock.
UA = "open_house-research/0.1 (institution domain-control check; contact via repo)"

TIMEOUT = 12

# Signals that a domain is serving something other than an institution. Word
# boundaries are mandatory: "judi" without one matches "Judicial", and the
# unbounded version of this list flagged the supreme courts of Mexico and The
# Gambia on its first run.
FLAGS = {
    "gambling": r"\b(togel|casino|kasino|judi|bandar|sbobet|slot ?gacor|maxwin|"
    r"situs ?(judi|slot)|taruhan|betting|poker|toto ?(resmi|online))\b",
    "adult": r"\b(porn|xxx|escort|hookup)\b",
    "parking": r"\b(domain (is )?for sale|buy this domain|this domain is|parked|"
    r"hugedomains|undeveloped|sedo|available for purchase|"
    r"expired domain|under construction)\b",
}

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

# Keyword flags catch a casino and miss everything else. apn-dz.org -- Algeria's
# National People's Assembly, lapsed and re-registered by a detective agency in
# Ichikawa -- trips none of them, because "探偵事務所" is not on any English
# blocklist and never will be. Chasing that with more keywords is a losing game.
#
# So the review list is built from EXPOSURE rather than from content. A body on
# gov.dz cannot have its domain quietly bought by a stranger; the registry will
# not sell it. A body on a .org or .com can, and apn-dz.org sat parked with
# "This website is for sale!" on it in 2015 before someone did. Generic-TLD
# institutional domains are where a lapse hides, there are only a couple of
# dozen of them, and a human can read that list in five minutes.
GENERIC_TLD = re.compile(r"\.(com|org|net|info|biz|co)$", re.I)
GOVERNMENTAL = re.compile(
    r"\.(gov|gob|gouv|go|govt|gv|gc|bund|admin)\.|" r"^gov\.|\.gov$|\.govt$|\.int$", re.I
)


def title_of(html):
    m = TITLE_RE.search(html or "")
    if not m:
        return ""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", m.group(1))).strip()[:200]


def fetch(domain):
    """One GET, both schemes tried, everything recorded including the failure.

    An unreachable homepage is NOT evidence that a domain was lost. Plenty of
    institutions sit behind a WAF that refuses a non-browser agent -- 82 of 502
    returned 403 on the first run -- and plenty simply have a broken
    certificate. The status is recorded so a reader can see the difference
    between "serves a casino" and "would not talk to us".
    """
    last = "no attempt"
    for scheme in ("https", "http"):
        try:
            r = requests.get(
                f"{scheme}://{domain}",
                timeout=TIMEOUT,
                headers={"User-Agent": UA},
                allow_redirects=True,
            )
            html = r.text if "html" in r.headers.get("content-type", "").lower() else ""
            title = title_of(html)
            return {
                "domain": domain,
                "http_status": r.status_code,
                "final_host": urlparse(r.url).netloc.lower().lstrip("www."),
                "title": title,
                "flag": next((k for k, pat in FLAGS.items() if re.search(pat, title, re.I)), ""),
                "error": "",
            }
        except requests.RequestException as exc:
            last = f"{type(exc).__name__}"
    return {
        "domain": domain,
        "http_status": None,
        "final_host": "",
        "title": "",
        "flag": "",
        "error": last,
    }


def main():
    frame = pd.read_csv(FRAME)
    domains = sorted(frame.domain.dropna().unique())
    print(f"==> fetching {len(domains):,} homepages, one GET each")

    with ThreadPoolExecutor(12) as ex:
        rows = list(ex.map(fetch, domains))
    out = pd.DataFrame(rows)
    out["checked_date"] = date.today().isoformat()
    out["source_id"] = "site_content"
    out.to_csv(OUT, index=False)

    out["generic_tld"] = out.domain.str.contains(GENERIC_TLD, na=False) & ~out.domain.str.contains(
        GOVERNMENTAL, na=False
    )
    out["review"] = out.flag.ne("") | out.generic_tld
    out.to_csv(OUT, index=False)

    ok = out.http_status.notna()
    print(f"\n  responded: {int(ok.sum())}   no response: {int((~ok).sum())}")
    print("  (no response is not evidence of a lost domain -- WAFs refuse " "non-browser agents)")
    flagged = out[out.flag != ""]
    print(f"\n  {len(flagged)} domains flagged by content:")
    for _, r in flagged.iterrows():
        print(f"    [{r.flag:8s}] {r.domain:34s} {r.title[:56]}")
    gen = out[out.generic_tld]
    print(f"\n  {len(gen)} institutional domains on a generic TLD -- where a lapse hides:")
    for _, r in gen.iterrows():
        print(f"    {r.domain:34s} {(r.title or '(no title)')[:56]}")
    print("\n  A FLAG IS A QUESTION, NOT A VERDICT. Record the answer in")
    print("  data/domain_control_review.csv before any analysis drops a domain.")
    print(f"\n  wrote {OUT}")


if __name__ == "__main__":
    main()
