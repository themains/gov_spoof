"""Build the sampling frame: national institutions and their web domains.

WHY A CENSUS, NOT A SAMPLE. There is no canonical global list of "government
domains" -- the US publishes several thousand .gov entries, most countries
publish nothing -- so any attempt at "all government domains" is a convenience
sample whose coverage tracks state capacity. That is precisely the bias that
makes cross-country comparisons of breach exposure uninterpretable, and it is
the reason this project exists.

Institutions are different. Every country has a legislature, a head of state, an
executive and a highest court, and Wikidata enumerates them. The frame is
therefore a CENSUS of national institutions rather than a sample of domains, and
country coverage is a property of the world rather than of who happened to
publish a directory.

    P194   legislative body              232 countries, 195 with a website
    P1906  office held by head of state  211 countries, 159 with a website
    P208   executive body                152 countries, 111 with a website
    P209   highest judicial authority    104 countries, 123 with a website

Four branches also allow a question one branch cannot: do the branches differ in
posture WITHIN a country? That comparison holds state capacity, wealth and
threat environment fixed by construction, which no cross-country regression can.

FILTERED ON HAVING AN ISO-3166 ALPHA-3 CODE (P298), not on being a sovereign
state. The sovereignty filter silently lost real countries, because composite
states are modeled differently:

    Netherlands  Q55 (ISO NLD) holds the States General but is a CONSTITUENT
                 country; the sovereign-state entity Q29999 has no P194 at all,
                 so the Netherlands vanished from the frame entirely.
    Denmark      Q35 (ISO DNK) holds the Folketing; the filter matched Q756617
                 (Kingdom of Denmark) instead, which has the legislature but no
                 ISO code -- rows that could not join to any covariate.

Requiring P298 fixes both and is better on its own terms: the ISO code is the
join key everything downstream needs. It admits territories (Hong Kong, Puerto
Rico, Guernsey), which have legislatures too, so sovereignty is recorded as a
FLAG rather than used as a gate.

FROZEN. Collection only; never runs as part of an analysis build.

Usage:  python scripts/collect/institution_frame.py
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
OUT = os.path.join(REPO, "data", "institution_domains.csv")

ENDPOINT = "https://query.wikidata.org/sparql"
# A descriptive agent is required by WDQS etiquette; anonymous scripted querying
# is what gets research traffic blocked.
UA = "open_house-research/0.1 (government attack surface; contact via repo)"

BRANCHES = {
    "P194": "legislature",
    "P1906": "head_of_state_office",
    "P208": "executive",
    "P209": "judiciary",
}

# The frame is ISO-CODED ENTITIES AND THEIR CONSTITUENT PARTS.
#
# Two failed attempts got here. Filtering on `P31 = sovereign state` dropped the
# Netherlands and mis-keyed Denmark. Making the ISO code optional then matched
# every jurisdiction on earth with a legislature -- 10,084 rows, because P194 is
# used for US states, German Laender, Indian states and municipal councils
# alike. Neither the country entity alone nor no filter at all is right.
#
# What actually holds: an institution belongs in the frame if it hangs off an
# entity carrying an ISO-3166 alpha-3 code, OR off an entity that is `part of`
# (P361) one. The second clause is what rescues composite states, where the code
# and the institution sit on different entities:
#
#     Q55 Netherlands  --P17-->   Q29999 Kingdom of the Netherlands (ISO NLD)
#     Q35 Denmark      --P361-->  Q756617 Kingdom of Denmark
#
# and neither pair has both facts on one entity. BOTH properties are needed:
# Denmark links by `part of` (P361), the Netherlands only by `country` (P17).
# An earlier diagnostic queried `P361 UNION P17` without labeling which
# property produced each row, and the Netherlands result was attributed to P361
# on no evidence -- so the first fix used P361 alone and silently lost the Dutch
# legislature while the country still appeared via its head of state, which is
# exactly why the frame assertion is now PER BRANCH.
# P576 (dissolved, abolished or demolished) and P582 (end time) are pulled
# because the frame was carrying bodies that no longer exist. Five sat INSIDE
# the measured sweep -- Mali's and Niger's national assemblies, dissolved after
# their coups; Norfolk Island's, abolished in 2015; Venezuela's, ended
# 2023-01-04; Kazakhstan's, dissolved 2026-07-01 -- and four of the five
# published no DMARC. An abandoned parliament's domain rots, so counting it
# reads as weak security in the branch that already looks worst.
#
# Recorded, NOT filtered. P576 does not distinguish "abolished" from "dissolved
# pending an election", and a rule that dropped every dated body would throw out
# a parliament that is merely between terms. The analysis decides; this records.
QUERY = """
SELECT ?country ?countryLabel ?iso3 ?body ?bodyLabel ?site ?sovereign
       ?dissolved ?ended WHERE {
  ?country wdt:%(prop)s ?body .
  OPTIONAL { ?country wdt:P298 ?iso3 }
  OPTIONAL { ?body wdt:P856 ?site }
  OPTIONAL { ?body wdt:P576 ?dissolved }
  OPTIONAL { ?body wdt:P582 ?ended }
  OPTIONAL { ?country wdt:P31 ?type . BIND(IF(?type = wd:Q3624078, true, 0) AS ?sovereign) }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "en". }
}
"""

# Countries whose absence means the frame is broken rather than that Wikidata is
# thin. The composite-state bug survived a full sweep and a commit because
# nothing ever asserted the frame was complete; this is that assertion.
MUST_BE_PRESENT = ["NLD", "DNK", "DEU", "FRA", "JPN", "BRA", "IND", "USA", "GBR"]
# Asserted for the LEGISLATURE specifically, not merely for the country. The
# country-level version of this check passed while the Dutch legislature was
# missing, because the Netherlands still appeared via its head of state.
MUST_HAVE_LEGISLATURE = MUST_BE_PRESENT


# Constituent countries that hold an institution while the ISO code sits on the
# parent state. Keyed by QID, deliberately, and deliberately SHORT.
#
# Name matching was tried and rejected: it is unsafe here. Wikidata's P194 is
# used at every level of government, so the raw result contains thousands of
# sub-national bodies, and a name lookup would resolve the US state of Georgia
# to the country GEO, Punjab to nothing, and so on -- inventing national
# institutions out of provincial ones. An explicit QID map cannot do that.
#
# Anything not in this map and without its own ISO code is DROPPED, which is how
# the frame stays national. The per-branch assertion below is what catches a
# composite state missing from this map.
CONSTITUENT_COUNTRIES = {
    "Q55": "NLD",   # Netherlands, within the Kingdom of the Netherlands
    "Q35": "DNK",   # Denmark, within the Kingdom of Denmark
}


def resolve_cc3(iso3, country_qid):
    """ISO-3 code from the entity's own P298, else from the constituent map."""
    return iso3 or CONSTITUENT_COUNTRIES.get(country_qid)


def host_of(url):
    """Host from a website URL, with a leading www stripped.

    Deliberately NOT reduced to a registrable domain via the public suffix list.
    An institution's mail domain is frequently a subdomain (sansad.nic.in under
    nic.in), and collapsing would measure the parent ministry's posture instead
    of this institution's -- a different body with a different configuration.
    """
    if not url:
        return None
    host = urlparse(str(url)).netloc.lower().strip()
    return (host[4:] if host.startswith("www.") else host) or None


def fetch(prop, today):
    """One query per branch, snapshotted before anything parses it."""
    snap = os.path.join(RAW, f"{prop}_{today}.json")
    if os.path.exists(snap):
        with open(snap) as fh:
            return json.load(fh)
    r = requests.get(ENDPOINT, params={"query": QUERY % {"prop": prop}, "format": "json"},
                     headers={"User-Agent": UA}, timeout=180)
    r.raise_for_status()
    payload = r.json()
    with open(snap, "w") as fh:
        json.dump(payload, fh, indent=1)
    return payload


def main():
    os.makedirs(RAW, exist_ok=True)
    today = date.today().isoformat()
    rows = []

    for prop, branch in BRANCHES.items():
        payload = fetch(prop, today)
        for b in payload["results"]["bindings"]:
            site = b.get("site", {}).get("value")
            rows.append({
                "branch": branch,
                "wikidata_property": prop,
                "country_qid": b["country"]["value"].rsplit("/", 1)[-1],
                "country": b.get("countryLabel", {}).get("value"),
                "cc3": resolve_cc3(b.get("iso3", {}).get("value"),
                                   b["country"]["value"].rsplit("/", 1)[-1]),
                "body_qid": b["body"]["value"].rsplit("/", 1)[-1],
                "body": b.get("bodyLabel", {}).get("value"),
                "sovereign": b.get("sovereign", {}).get("value") in ("true", "1"),
                "website": site,
                "domain": host_of(site),
                "dissolved_date": (b.get("dissolved", {}).get("value")
                                   or b.get("ended", {}).get("value") or None),
                "domain_source": "wikidata_p856" if site else None,
            })
        print(f"  {branch:<22} {len(payload['results']['bindings']):>4} rows")

    df = pd.DataFrame(rows)
    # Everything without a country code is sub-national and out of scope.
    national = df.cc3.notna()
    print(f"\n  dropped {int((~national).sum()):,} sub-national rows "
          f"(P194 and friends are used at every level of government)")
    df = df[national].copy()
    # A body can carry several P31 values, so sovereignty arrives as several
    # rows; collapse to any-true before deduplicating.
    df["sovereign"] = df.groupby("country_qid")["sovereign"].transform("max")
    # Same shape of problem as sovereign: a body can carry more than one
    # dissolution or end date and arrives as one row per value. Collapse to the
    # earliest before deduplicating, or the drop_duplicates below would keep
    # several rows for one institution and inflate every count downstream.
    df["dissolved_date"] = df.groupby(["branch", "body_qid"])["dissolved_date"].transform("min")
    df = df.drop_duplicates(["branch", "body_qid", "domain"])

    legs = set(df.cc3[df.branch == "legislature"].dropna())
    absent = [c for c in MUST_HAVE_LEGISLATURE if c not in legs]
    if absent:
        sys.exit(
            f"frame is incomplete: {', '.join(absent)} missing. This is the "
            "composite-state failure -- check whether the institution hangs off "
            "the constituent country rather than the kingdom."
        )

    # Fold in the websites resolved from Wikipedia and reviewed by hand. These
    # carry domain_source='resolved' all the way to the posture table, because
    # an expansion whose additions cannot be separated from the original frame
    # is an expansion nobody can audit: resolution succeeds more often in
    # well-documented countries, and every result therefore has to be
    # computable on the Wikidata-sourced domains alone.
    review_path = os.path.join(REPO, "data", "institution_sites_review.csv")
    if os.path.exists(review_path):
        acc = pd.read_csv(review_path)
        acc = acc[acc.verdict == "accept"].set_index("body_qid").candidate_domain
        fill = df.body_qid.map(acc)
        newly = df.domain.isna() & fill.notna()
        df.loc[newly, "domain"] = fill[newly]
        df.loc[newly, "domain_source"] = "resolved"
        print(f"\n  merged {int(newly.sum())} hand-reviewed resolved websites")
    else:
        print("\n  no institution_sites_review.csv; frame is Wikidata-only")

    df = df.sort_values(["country", "branch", "body"])
    df["retrieved_date"] = today
    df["source_id"] = "wikidata"
    df.to_csv(OUT, index=False)

    have = df.domain.notna()
    print(f"\n  frame check: all {len(MUST_BE_PRESENT)} must-be-present countries found")
    print(f"  {df.cc3.nunique()} jurisdictions, {df.body_qid.nunique()} institutions")
    print(f"  {int(have.sum())} rows with a resolvable domain, "
          f"{int((~have).sum())} without (kept, so the denominator stays honest)")
    print(f"  {df.domain.dropna().nunique()} distinct domains to sweep")

    gone = df.dissolved_date.notna()
    print(f"\n  {int(gone.sum())} rows carry a dissolution or end date, "
          f"{int((gone & have).sum())} of them WITH a domain.")
    print("  Kept and flagged, not dropped: P576 does not separate 'abolished'")
    print("  from 'dissolved before an election'. Review them individually.")
    if int((gone & have).sum()):
        for _, r in df[gone & have].iterrows():
            print(f"    {r.cc3} {r.branch:<20} {str(r.domain):<34} {r.dissolved_date[:10]}")
    print("\n  by branch:")
    for br, g in df.groupby("branch"):
        print(f"    {br:<22} {g.cc3.nunique():>3} jurisdictions, "
              f"{g.domain.notna().sum():>3} with a domain")
    print(f"\n  wrote {OUT}")


if __name__ == "__main__":
    main()
