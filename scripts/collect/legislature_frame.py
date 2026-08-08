"""Build the sampling frame: national legislatures and their web domains.

The unit of analysis for this project is the legislature, so the frame has to be
a list of legislatures rather than a list of politicians. Wikidata supplies it
directly: sovereign states (Q3624078) carry a `legislative body` property
(P194), and legislatures carry an `official website` (P856).

    195 sovereign states, 197 legislative bodies, 169 with a website

Wikidata rather than govdirectory.org, even though a sibling project
(themains/private_gov) already parses govdirectory TSVs. Two reasons:
govdirectory is itself Wikidata-derived — its own URLs are keyed by QID — so
this is the upstream source rather than a different one; and the local
govdirectory copy covers 34 countries against 195 here. A single query also
makes the frame reproducible and re-runnable, where a folder of hand-downloaded
TSVs is neither.

The QID is retained on every row. It is the join key to everything else
Wikidata knows about a legislature, and it is what lets this frame be linked to
the politician-level data in themains/pwned_pols, which resolves people to QIDs.

FROZEN. Collection only; never runs as part of an analysis build.

Usage:  python scripts/collect/legislature_frame.py
"""

import json
import os
import sys
from datetime import date
from urllib.parse import urlparse

import pandas as pd
import requests

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
RAW = os.path.join(REPO, "data", "raw", "wikidata")
OUT = os.path.join(REPO, "data", "legislature_domains.csv")

ENDPOINT = "https://query.wikidata.org/sparql"
# A descriptive agent is required by the WDQS etiquette policy; anonymous
# scripted querying is what gets research traffic blocked.
UA = "open_house-research/0.1 (legislature attack surface; contact via repo)"

QUERY = """
SELECT ?country ?countryLabel ?iso3 ?leg ?legLabel ?site WHERE {
  ?country wdt:P31 wd:Q3624078 ;
           wdt:P194 ?leg .
  OPTIONAL { ?country wdt:P298 ?iso3 }
  OPTIONAL { ?leg wdt:P856 ?site }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "en". }
}
"""


def registrable_domain(url):
    """Host from a website URL, with a leading www stripped.

    Deliberately NOT reduced to a registrable domain via the public suffix
    list. A legislature's mail domain is frequently a subdomain
    (sansad.nic.in under nic.in), and collapsing to the registrable domain
    would measure the parent ministry's posture instead of the parliament's --
    a different institution with a different configuration.
    """
    if not url:
        return None
    host = urlparse(str(url)).netloc.lower().strip()
    if not host:
        return None
    return host[4:] if host.startswith("www.") else host


def main():
    os.makedirs(RAW, exist_ok=True)
    today = date.today().isoformat()
    snapshot = os.path.join(RAW, f"legislatures_{today}.json")

    if os.path.exists(snapshot):
        print(f"  using existing snapshot {os.path.basename(snapshot)}")
        with open(snapshot) as fh:
            payload = json.load(fh)
    else:
        r = requests.get(
            ENDPOINT,
            params={"query": QUERY, "format": "json"},
            headers={"User-Agent": UA},
            timeout=180,
        )
        r.raise_for_status()
        payload = r.json()
        with open(snapshot, "w") as fh:
            json.dump(payload, fh, indent=1)
        print(f"  queried Wikidata, snapshot written")

    rows = []
    for b in payload["results"]["bindings"]:
        site = b.get("site", {}).get("value")
        rows.append({
            "country_qid": b["country"]["value"].rsplit("/", 1)[-1],
            "country": b.get("countryLabel", {}).get("value"),
            "cc3": b.get("iso3", {}).get("value"),
            "legislature_qid": b["leg"]["value"].rsplit("/", 1)[-1],
            "legislature": b.get("legLabel", {}).get("value"),
            "website": site,
            "domain": registrable_domain(site),
        })

    df = pd.DataFrame(rows).drop_duplicates(["legislature_qid", "domain"])

    # A legislature with no published website cannot be measured, and dropping
    # it silently would understate how many are unmeasurable. Kept in the frame
    # with a null domain so the denominator stays honest.
    have = df.domain.notna()
    df = df.sort_values(["country", "legislature"])
    df["retrieved_date"] = today
    df["source_id"] = "wikidata_p194"
    df.to_csv(OUT, index=False)

    print(f"\n  {df.country_qid.nunique()} sovereign states")
    print(f"  {df.legislature_qid.nunique()} legislative bodies")
    print(f"  {int(have.sum())} with a resolvable domain "
          f"({100 * have.mean():.0f}%); {int((~have).sum())} without, kept as unmeasurable")
    missing_iso = df.cc3.isna().sum()
    if missing_iso:
        print(f"  {missing_iso} rows without an ISO-3 code -- these cannot join "
              f"to country covariates and must be handled explicitly")
    print(f"  wrote {OUT}")


if __name__ == "__main__":
    main()
