"""Collection adapter: find the websites Wikidata does not have.

212 live institutions sit in the frame with no domain, because `P856` is empty
for them. They are not obscure -- the Supreme Court of Uruguay, the Congress of
the Philippines, the Government of Denmark -- and their absence is what keeps
the within-country comparison thin: supreme courts are measured in 78 countries
against 169 for legislatures, so the branch table compares different worlds.

WHY WIKIPEDIA FIRST, THEN SEARCH. A Wikipedia infobox `website =` field is
maintained by different people, under different rules, from Wikidata's `P856`,
which is exactly why it holds values where `P856` is blank. It is also
scriptable, so this whole pass re-runs and reproduces instead of being a thing
somebody once did. Search fills the residual.

WHAT NOT TO DO, LEARNED THE EXPENSIVE WAY. The first attempt took the first
external link on the article. That is a citation, not a homepage, and it
produced: President of Senegal -> businessdailyafrica.com, Legislature of
Liberia -> liberianobserver.com, Supreme Court of Syria -> an NGO's PDF. All
three look entirely plausible in a table. Matching on names is no safer: pattern
matching "executive branch of the Government of India" against a government
directory returned the Ministry of Road Transport and Highways, with confidence.

So a candidate is only ever a CANDIDATE. It has to survive validate(), and the
evidence that produced it is written next to it so a reader can reject a
specific decision rather than the whole exercise.

THE BIAS IS REAL AND IS NOT FIXABLE HERE. An institution is easier to resolve
when its country is well documented, which is the same gradient that makes the
frame thin in the first place. The answer is to measure it, not to deny it:
`domain_source` travels into the posture table so every result can be computed
on Wikidata-sourced domains alone and on the expanded set, and the analysis
reports the resolution rate by branch and region.

FROZEN. Listed in FROZEN_COLLECTORS; never runs in a build.

Usage:  python scripts/collect/resolve_missing_sites.py [--limit N]
"""

import argparse
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date
from urllib.parse import urlparse

import pandas as pd

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
RAW = os.path.join(REPO, "data", "raw", "resolve_sites")
FRAME = os.path.join(REPO, "data", "institution_domains.csv")
OUT = os.path.join(REPO, "data", "institution_sites_resolved.csv")

UA = "open_house-research/0.1 (institution website resolution; contact via repo)"

# Wikis that are not language encyclopaedias. commonswiki and friends have
# sitelinks for many of these entities and none of them carry an infobox.
BADWIKI = re.compile(
    r"^(commons|species|meta|incubator|wikidata|simple)|"
    r"(source|quote|news|voyage|books|versity|data)wiki$"
)

# The infobox field, in the handful of languages the frame actually lands in.
FIELD = re.compile(
    r"^\s*\|\s*(website|url|homepage|site_?web|sitio_?web|" r"webseite|sito|сайт)\s*=\s*(.+)$",
    re.I | re.M,
)
URL_TEMPLATE = re.compile(
    r"\{\{\s*(?:URL|Official ?website|Site officiel|" r"Официальный сайт)\s*\|\s*(?:1=)?([^}|]+)",
    re.I,
)
BARE_URL = re.compile(r"https?://[^\s\]\}\|<]+")

# Domains that are never an institution's own site. News outlets are the
# dangerous class: they are topical, look authoritative, and are what a naive
# extractor grabs first.
NEVER = re.compile(
    r"wikipedia|wikimedia|wikidata|archive\.org|web\.archive|facebook|twitter|x\.com|"
    r"youtube|instagram|linkedin|flickr|google\.|doi\.org|jstor|britannica|"
    r"constitutionnet|refworld|reuters|bbc\.|aljazeera|apnews|afp\.com|"
    r"observer|dailynews|businessdaily|news24|allafrica|worldbank|un\.org",
    re.I,
)


# Offices that cannot have an institutional website, because the office is a
# person and frequently a person shared with fifteen other realms. "monarch of
# Australia" is Charles III; there is no australian-crown.gov.au to find, and a
# search for one returns the royal.uk page or a news article. 33 of the 212
# missing entries are this. They are RECORDED as not_applicable rather than
# dropped, so the resolution rate below is not quietly computed against a
# denominator that excluded everything hard.
#
# "President of X" is deliberately NOT in this class: those are real offices with
# real staff and, usually, real domains.
SHARED_CROWN = re.compile(
    r"^(monarch|king|queen|sultan|emir|emperor|grand duke|prince|"
    r"(episcopal|french) co-?prince|co-?prince)\b",
    re.I,
)


def host_of(url):
    h = urlparse(str(url).strip()).netloc.lower().strip()
    return (h[4:] if h.startswith("www.") else h) or None


def get(url, tries=5):
    """One API call, backing off on 429 rather than hammering.

    Wikimedia returns 429 readily to a scripted client, and a probe run that
    ignored it died a third of the way through. Backoff here is not politeness
    theatre; without it this collector cannot finish.
    """
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            return json.load(urllib.request.urlopen(req, timeout=60))
        except urllib.error.HTTPError as exc:
            if exc.code != 429 or attempt == tries - 1:
                raise
            time.sleep(3 * (attempt + 1))
        except Exception:
            if attempt == tries - 1:
                raise
            time.sleep(2 * (attempt + 1))


def pick_wiki(sitelinks):
    if "enwiki" in sitelinks:
        return "en", sitelinks["enwiki"]["title"]
    for key, val in sitelinks.items():
        if key.endswith("wiki") and not BADWIKI.search(key):
            return key[:-4], val["title"]
    return None, None


def extract(wikitext):
    """The infobox website field, or an {{Official website}} template.

    Deliberately not "the first URL in the article": see the module docstring.
    """
    for m in FIELD.finditer(wikitext or ""):
        value = m.group(2)
        t = URL_TEMPLATE.search(value)
        if t:
            return t.group(1).strip()
        u = BARE_URL.search(value)
        if u:
            return u.group(0).strip()
    t = URL_TEMPLATE.search(wikitext or "")
    return t.group(1).strip() if t else None


# Second pass, for the 123 institutions whose article has no infobox website
# field. Their "Official website" is usually still on the page, in the external
# links, next to a dozen citations. Taking the first country-plausible link gets
# it right about half the time and wrong in a specific, diagnosable way: it
# returns the wrong ORGAN of the right state. Laos's President resolved to
# Japan's Ministry of Finance, Botswana's President to parliament.gov.bw,
# Anguilla's House of Assembly to legislation.gov.uk.
#
# So candidates are ranked by whether the hostname itself names the branch. That
# is not proof -- senado.gov.co is a chamber of Colombia's Congress and
# alcaldiabogota.gov.co is the mayor of Bogota, and only the first contains a
# legislature word -- but it is a signal that survives inspection, and every
# candidate still goes to a human.
BRANCH_HINT = {
    "legislature": r"parl|assemb|senat|senad|congres|majlis|duma|shura|diet|knesset|"
    r"folketing|riksdag|storting|sabor|skupstina|legislat|chamber|"
    r"camara|tynwald|oireachtas|cortes|seimas|rada|nationalcouncil|hof",
    "judiciary": r"court|cour|tribunal|justic|judicial|judiciary|supremo|cassation|"
    r"sud|mahkam|scj|hoge|domstol",
    "executive": r"gouv|cabinet|primature|premier|chancell|statehouse|kabinet|regering|"
    r"regjering|vlada|govern|gov\.|gob\.|\bgov$|ministr",
    "head_of_state_office": r"presiden|presidence|presidencia|emansion|palace|palais|"
    r"akorda|kremlin|statehouse|royal|monarch",
}


def rank_candidates(domains, branch):
    """Branch-matching hostnames first, everything else after, order preserved."""
    hint = re.compile(BRANCH_HINT.get(branch, r"$^"), re.I)
    on = [d for d in domains if hint.search(d)]
    off = [d for d in domains if not hint.search(d)]
    return on + off


def exists_in_dns(domain):
    """Does the name exist at all? NOT "does it have an A record".

    The first version asked socket.getaddrinfo, which answers only for A/AAAA,
    and rejected eight live domains as dead. A mail domain needs no address
    record whatsoever: pcm.gob.pe -- Peru's Presidency of the Council of
    Ministers -- has no A record, an Outlook MX, and `v=DMARC1; p=reject`. It
    was thrown away as non-existent by a check that measured the wrong thing,
    which is the exact failure this project keeps finding in other people's
    work and has now committed twice in its own.

    NXDOMAIN is the only honest test of existence, and it is asked of a resolver
    known to answer rather than of whatever /etc/resolv.conf names.
    """
    import dns.resolver

    r = dns.resolver.Resolver(configure=False)
    r.nameservers, r.timeout, r.lifetime = ["1.1.1.1", "8.8.8.8"], 4, 8
    for rdtype in ("NS", "SOA", "MX", "A"):
        try:
            r.resolve(domain, rdtype)
            return True
        except dns.resolver.NXDOMAIN:
            return False
        except Exception:  # noqa: BLE001 - NoAnswer means the name exists
            continue
    return True


def validate(domain, cc2):
    """Return (decision, reason). Nothing here is allowed to say 'accept'.

    The mechanical checks can rule a candidate OUT -- a news domain, a
    non-hostname, a name that does not exist. They cannot rule one IN, and the
    first version of this function pretending otherwise produced
    maga.gob.gt for Guatemala's Council of Ministers. That is the Ministry of
    Agriculture. It passed because the ccTLD matched, which confirms the
    COUNTRY and says nothing at all about the INSTITUTION -- the same mistake,
    in a new costume, as matching "executive branch of the Government of India"
    to the Ministry of Road Transport.

    So everything that survives goes to `review`, and a person decides with the
    evidence in front of them. There are only ~40; that is a morning's work, not
    a reason to automate a judgement that cannot be automated.
    """
    if not domain:
        return "none_found", "no website field in the article"
    if NEVER.search(domain):
        return "reject", f"{domain} is a news outlet, aggregator or social platform"
    if "." not in domain or len(domain) < 4 or re.fullmatch(r"[\d.]+", domain):
        return "reject", f"{domain} is not a hostname"
    if not exists_in_dns(domain):
        return "reject", f"{domain} does not exist in DNS (NXDOMAIN)"
    tld = domain.rsplit(".", 1)[-1].lower()
    govish = bool(re.search(r"\.(gov|gob|gouv|go|govt|gv|gc|admin)\.", domain, re.I))
    country_ok = (cc2 and tld == cc2.lower()) or govish or tld == "int"
    if not country_ok:
        return "review", f"generic TLD .{tld}, and nothing ties it to the jurisdiction"
    return "review", (
        f"exists in DNS and the domain is plausible for the country"
        f"{' (ccTLD)' if cc2 and tld == cc2.lower() else ' (gov domain)'}; "
        "a human must confirm it is this institution"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()
    os.makedirs(RAW, exist_ok=True)
    today = date.today().isoformat()

    frame = pd.read_csv(FRAME)
    # Dissolved bodies are skipped: an abolished parliament has no current
    # website, and searching for one invents a domain for an institution that
    # does not exist.
    todo = frame[frame.domain.isna() & frame.dissolved_date.isna()].drop_duplicates("body_qid")

    # Institutions of states that no longer exist. `dissolved_date` catches a
    # body that was abolished; it does not catch a body whose COUNTRY was.
    # Czechoslovakia's Constituent National Assembly and the Chairman of the
    # Supreme Soviet survived the first filter and would otherwise have been
    # sent to a search engine to find a homepage for the USSR.
    import pycountry

    current = {c.alpha_3 for c in pycountry.countries} | {"XKS", "CRQ"}
    todo = todo.copy()
    todo["skip"] = ""
    todo.loc[~todo.cc3.isin(current), "skip"] = "state no longer exists"
    todo.loc[todo.body.str.contains(SHARED_CROWN, regex=True), "skip"] = (
        "office is a person, often a shared crown; no institutional site exists"
    )
    skipped = [
        {
            "body_qid": r.body_qid,
            "body": r.body,
            "country": r.country,
            "cc3": r.cc3,
            "branch": r.branch,
            "candidate_domain": None,
            "candidate_url": None,
            "evidence_url": None,
            "evidence": "",
            "decision": "not_applicable",
            "reason": r.skip,
            "resolved_date": today,
            "resolver": "rule",
        }
        for _, r in todo[todo.skip != ""].iterrows()
    ]
    live = todo[todo.skip == ""]
    print(f"==> {len(todo)} institutions with no website")
    print(f"    {len(skipped)} not applicable and recorded as such")
    print(f"    {len(live)} to resolve")
    todo = live.head(args.limit) if args.limit else live

    snap_path = os.path.join(RAW, f"wikipedia_{today}.json")
    cache = {}
    if os.path.exists(snap_path):
        with open(snap_path) as fh:
            cache = json.load(fh)
        print(f"  resuming: {len(cache)} already fetched")

    qids = [q for q in todo.body_qid if q not in cache]
    for i in range(0, len(qids), 40):
        batch = qids[i : i + 40]
        ents = get(
            "https://www.wikidata.org/w/api.php?action=wbgetentities&format=json"
            "&props=sitelinks&ids=" + "|".join(batch)
        )["entities"]
        for q in batch:
            lang, article = pick_wiki(ents.get(q, {}).get("sitelinks") or {})
            rec = {"lang": lang, "article": article, "wikitext": None}
            if article:
                try:
                    d = get(
                        f"https://{lang}.wikipedia.org/w/api.php?action=parse&format=json"
                        f"&prop=wikitext&page={urllib.parse.quote(article)}"
                    )
                    rec["wikitext"] = d["parse"]["wikitext"]["*"]
                except Exception as exc:  # noqa: BLE001
                    rec["error"] = f"{type(exc).__name__}"
            cache[q] = rec
            time.sleep(0.25)
        with open(snap_path, "w") as fh:
            json.dump(cache, fh)
        print(f"  {min(i + 40, len(qids)):>4}/{len(qids)} (snapshot saved)", flush=True)

    rows = []
    for _, r in todo.iterrows():
        rec = cache.get(r.body_qid, {})
        url = extract(rec.get("wikitext"))
        domain = host_of(url) if url else None
        try:
            cc2 = pycountry.countries.get(alpha_3=r.cc3).alpha_2
        except Exception:  # noqa: BLE001
            cc2 = None
        decision, reason = validate(domain, cc2)
        rows.append(
            {
                "body_qid": r.body_qid,
                "body": r.body,
                "country": r.country,
                "cc3": r.cc3,
                "branch": r.branch,
                "candidate_domain": domain,
                "candidate_url": url,
                "evidence_url": (
                    f"https://{rec['lang']}.wikipedia.org/wiki/"
                    f"{urllib.parse.quote(rec['article'])}"
                    if rec.get("article")
                    else None
                ),
                "evidence": (
                    f"infobox website field on the {rec.get('lang')} Wikipedia article"
                    if url
                    else "no infobox website field"
                ),
                "decision": decision,
                "reason": reason,
                "resolved_date": today,
                "resolver": "wikipedia-infobox",
            }
        )

    out = pd.DataFrame(rows + skipped)
    out.to_csv(OUT, index=False)
    print("\n  " + ", ".join(f"{k} {v}" for k, v in out.decision.value_counts().items()))
    print(f"\n  accepted automatically: {int((out.decision == 'accept').sum())}")
    print(f"  need a human decision:  {int((out.decision == 'review').sum())}")
    print(
        f"  no candidate at all:     {int((out.decision == 'none_found').sum())} "
        "-- these are the ones search has to cover"
    )
    print(f"\n  wrote {OUT}")


if __name__ == "__main__":
    main()
