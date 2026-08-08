"""Collection adapter: email-authentication posture of national legislatures.

Measures the PHISHING surface of every legislature in the frame. From EuRepoC's
coded initial-access techniques,
phishing is the single largest entry vector into political targets at 35.4% --
more than three times the share attributable to stolen credentials (10.9%),
which is the only vector the rest of this project measures. A domain without an
enforcing DMARC policy can be spoofed, and spoofing is how phishing at
institutions usually starts.

Uses `checkdmarc` rather than a hand-rolled resolver. That package already
parses and validates SPF (including the ten-DNS-lookup limit, which is fiddly
and easy to get wrong), DMARC, MTA-STS, SMTP-TLS reporting, DNSSEC and MX
STARTTLS. Reimplementing it would add bugs and no capability.

THE ONE THING THE WRAPPER MUST ADD is the distinction between "this domain
publishes no DMARC record" and "we could not find out". They are not the same
fact and conflating them manufactures findings. The very first three-domain test
hit it: bunge.go.tz returned no DMARC because the lookup timed out, not because
Tanzania's parliament publishes nothing. The same failure already cost this
project once -- 150 of the 154 domains rejected by the existing MX validation
failed on transient timeout rather than NXDOMAIN, silently dropping ~270 real
addresses from the analysis.

So every record here carries a STATUS, and a timeout is `lookup_failed`, never
`absent`. Downstream analysis must treat `lookup_failed` as missing data.

FROZEN. Listed in FROZEN_COLLECTORS; never runs in a build.

Usage:  python scripts/collect/dns_posture.py [--limit N]
"""

import argparse
import json
import os
import sys
from datetime import date

import pandas as pd

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
RAW = os.path.join(REPO, "data", "raw", "dns_posture")
OUT = os.path.join(REPO, "data", "legislature_dns_posture.csv")

# Preferred public resolvers, matching 05_validate_email_domains. Pinning makes
# a measurement reproducible rather than dependent on whatever the local network
# hands out -- but only where they are reachable, which cannot be assumed.
#
# On the machine this was first run on, outbound DNS to all three was blocked
# while the system resolver answered in 0.02s. Pinning them regardless turned a
# three-minute batch into twenty-nine minutes and would have scored every domain
# `lookup_failed` -- a table of garbage that reads exactly like a finding about
# parliaments. So the resolver is CHOSEN AT RUNTIME by testing it, and which one
# was used is recorded in the output.
PREFERRED_NAMESERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
PROBE = "_dmarc.parliament.uk"


def working_resolver():
    """Return (resolver, label). Prefer pinned public resolvers; fall back.

    Returns a configured resolver object rather than a nameserver list because
    checkdmarc otherwise constructs a bare dns.resolver.Resolver() inside its
    DNSSEC/TLSA path, which reads /etc/resolv.conf and raises
    NoResolverConfiguration on hosts that have none -- killing a long run
    partway through with nothing written.
    """
    import dns.resolver

    for ns in PREFERRED_NAMESERVERS:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers, r.timeout, r.lifetime = [ns], 3, 3
        try:
            r.resolve(PROBE, "TXT")
            return r, ns
        except Exception:  # noqa: BLE001 - unreachable is the only thing that matters
            continue

    r = dns.resolver.Resolver()
    try:
        r.resolve(PROBE, "TXT")
        return r, "system"
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"no working DNS resolver: {exc}")

# Errors that mean "we failed to ask", as opposed to "the answer is no".
TRANSIENT = ("timed out", "resolution lifetime expired", "no nameservers",
             "connection", "temporary", "batch error")


def status_of(block):
    """Classify a checkdmarc sub-result as ok / absent / lookup_failed.

    checkdmarc reports both a missing record and a failed lookup as valid=False
    with a message in `error`. Separating them is the whole point of this
    wrapper, so the classification is explicit and errors that match nothing
    known fall through to lookup_failed rather than being assumed absent --
    failing toward "we do not know" is the safe direction.
    """
    if not isinstance(block, dict):
        return "lookup_failed", None
    if block.get("valid"):
        return "ok", block.get("error")
    err = str(block.get("error") or "").lower()
    if not err:
        return "absent", None
    if any(t in err for t in TRANSIENT):
        return "lookup_failed", block.get("error")
    # A syntactically broken record is present-but-wrong, which is a different
    # and interesting state: the domain owner tried and failed.
    return "invalid", block.get("error")


def spf_qualifier(record):
    """The 'all' qualifier decides whether SPF actually rejects anything.

    -all is a hard fail, ~all a soft fail that most receivers accept anyway, and
    +all is worse than no record at all because it authorises the world.
    """
    if not record:
        return None
    r = str(record).lower()
    for token, label in (("-all", "hard_fail"), ("~all", "soft_fail"),
                         ("?all", "neutral"), ("+all", "pass_all")):
        if token in r:
            return label
    return "no_all"


def domains_from_frame():
    """One row per legislature domain, from the Wikidata-derived frame.

    A legislature may publish several domains -- the Folketing has four, one of
    them Faroese and one Greenlandic -- and each is a separate surface to
    secure, so each is measured. Aggregating to the institution is an analysis
    decision made later, not a collection one made here.

    Legislatures with no published website stay out of the sweep but remain in
    the frame with a null domain, so the denominator of "how many could be
    measured" is not quietly reduced to "how many were".
    """
    frame = pd.read_csv(os.path.join(REPO, "data", "legislature_domains.csv"))
    have = frame[frame.domain.notna()].copy()
    return (
        have[["domain", "country", "cc3", "legislature", "legislature_qid"]]
        .drop_duplicates("domain")
        .sort_values(["country", "domain"])
        .reset_index(drop=True)
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=None,
                    help="only the N largest domains; for a pilot run")
    args = ap.parse_args()

    try:
        from checkdmarc import check_domains
    except ImportError:
        sys.exit("checkdmarc is not installed. pip install checkdmarc")

    resolver, ns_label = working_resolver()
    print(f"==> resolver: {ns_label}")

    dom = domains_from_frame()
    if args.limit:
        dom = dom.head(args.limit)
    print(f"==> checking {len(dom):,} domains")

    os.makedirs(RAW, exist_ok=True)
    today = date.today().isoformat()

    # A configured resolver OBJECT is passed, not a nameserver list. Passing a
    # list leaves checkdmarc free to construct a bare dns.resolver.Resolver()
    # inside its DNSSEC/TLSA path, which reads /etc/resolv.conf and raises
    # NoResolverConfiguration on hosts that have none -- which is how the first
    # full run died partway through with nothing written.
    #
    # skip_tls: connecting to MX hosts to test STARTTLS would be active contact
    # with mail infrastructure. Everything here stays passive DNS lookups.
    #
    # Chunked, because a single unhandled resolver error should cost one batch
    # rather than the whole sweep.
    results = []
    domains = list(dom.domain)
    CHUNK = 25
    for i in range(0, len(domains), CHUNK):
        batch = domains[i:i + CHUNK]
        try:
            # timeout/retries left at checkdmarc's defaults. Raising them to
            # 5.0/1 pushed 50 domains past ten minutes, and a longer timeout
            # does not buy much here: a resolver that has not answered in two
            # seconds is recorded as lookup_failed, which is the honest outcome
            # anyway. Speed matters because the sweep is meant to be repeatable.
            r = check_domains(batch, skip_tls=True, resolver=resolver)
            results.extend([r] if isinstance(r, dict) else r)
        except Exception as exc:  # noqa: BLE001 - one bad batch must not end the run
            print(f"  batch {i}-{i + len(batch)} failed: {type(exc).__name__}: {exc}")
            for d in batch:
                results.append({"domain": d, "dmarc": {"valid": False,
                                                       "error": f"batch error: {exc}"}})
        print(f"  {min(i + CHUNK, len(domains)):>4}/{len(domains)}", flush=True)

    with open(os.path.join(RAW, f"checkdmarc_{today}.json"), "w") as fh:
        json.dump(results, fh, indent=1, default=str)

    rows = []
    for res in results:
        dmarc, spf = res.get("dmarc", {}), res.get("spf", {})
        d_status, d_err = status_of(dmarc)
        s_status, s_err = status_of(spf)
        policy = None
        tags = dmarc.get("tags") if isinstance(dmarc, dict) else None
        if isinstance(tags, dict):
            policy = (tags.get("p") or {}).get("value")
        rows.append({
            "domain": res.get("domain"),
            "dmarc_status": d_status,
            "dmarc_policy": policy,
            "dmarc_error": d_err,
            "spf_status": s_status,
            "spf_qualifier": spf_qualifier(spf.get("record") if isinstance(spf, dict) else None),
            "spf_error": s_err,
            "mta_sts": status_of(res.get("mta_sts"))[0],
            "dnssec": res.get("dnssec"),
            "checked_date": today,
            "resolver": ns_label,
            "source_id": "dns_posture",
        })

    out = pd.DataFrame(rows).merge(dom, on="domain", how="left")
    out.to_csv(OUT, index=False)

    n = len(out)
    print(f"\n  dmarc: " + ", ".join(
        f"{k} {v}" for k, v in out.dmarc_status.value_counts().items()))
    print(f"  policy among valid: " + ", ".join(
        f"{k} {v}" for k, v in out.dmarc_policy.value_counts(dropna=False).items()))
    failed = (out.dmarc_status == "lookup_failed").sum()
    print(f"\n  {failed} of {n} DMARC lookups FAILED and are recorded as missing,")
    print("  not as 'no DMARC'. Treat them as missing downstream.")
    print(f"  wrote {OUT}")


if __name__ == "__main__":
    main()
