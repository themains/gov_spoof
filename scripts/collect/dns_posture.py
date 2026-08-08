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

# checkdmarc signals every negative outcome identically -- valid=False plus a
# message -- so the message text is the only thing separating four very
# different facts.
#
# The first version of this file assumed an EMPTY error meant "publishes no
# record". checkdmarc does not behave that way: it returns a sentence saying so.
# The result was 55 legislatures that publish no DMARC at all being recorded as
# publishing a BROKEN one -- the same category confusion this wrapper exists to
# prevent, reached from the other side. Caught by noticing that 62 of 165
# "invalid" was implausibly high and reading the actual strings.
#
# Order matters: "The domain does not exist" also contains "does not exist", so
# NXDOMAIN is tested before ABSENT.

# The domain itself does not resolve. Not a DMARC fact at all -- it means the
# FRAME is stale: Wikidata lists a website that has since gone away.
NXDOMAIN = ("the domain does not exist",)

# The domain resolves and publishes no such record. A real, measurable finding.
ABSENT = ("record does not exist", "no dmarc record", "no spf record",
          "does not have a dmarc record", "does not have an spf record")

# We failed to ask. Not a finding; missing data.
TRANSIENT = ("timed out", "resolution lifetime expired", "no nameservers",
             "nameservers failed to answer", "connection", "temporary",
             "batch error")


def status_of(block):
    """Classify a checkdmarc sub-result.

    Returns one of:
      ok            a valid record is published
      absent        the domain resolves and publishes none
      invalid       a record is published but is malformed -- they tried and failed
      nxdomain      the domain does not resolve; a frame problem, not a posture one
      lookup_failed we could not find out; treat as missing

    Anything unrecognised falls through to lookup_failed rather than to absent,
    so an unfamiliar error can never be mistaken for a finding.
    """
    if not isinstance(block, dict):
        return "lookup_failed", None
    if block.get("valid"):
        return "ok", block.get("error")
    err = str(block.get("error") or "").lower()
    if not err:
        return "absent", None
    if any(t in err for t in NXDOMAIN):
        return "nxdomain", block.get("error")
    if any(t in err for t in TRANSIENT):
        return "lookup_failed", block.get("error")
    if any(t in err for t in ABSENT):
        return "absent", block.get("error")
    # Published but malformed: a distinct and interesting state, and a different
    # remedy from never having tried.
    return "invalid", block.get("error")


def spf_qualifier(spf):
    """The effective `all` qualifier, taken from checkdmarc's parsed output.

    This previously substring-matched "-all"/"~all" against the raw record --
    hand-rolling something the library already does properly, and getting it
    wrong on exactly the hard cases. It disagreed with checkdmarc on 4 of 125
    records, and the two it called "no_all" were the two using `redirect=`,
    where the effective policy comes from the redirect target and there is no
    literal `all` token to find. Substring matching would also cheerfully match
    an "-all" appearing inside an exp= string.

    checkdmarc resolves the redirect chain and returns 'fail', 'softfail',
    'neutral' or 'pass'. Use that.
    """
    if not isinstance(spf, dict):
        return None
    parsed = spf.get("parsed")
    return parsed.get("all") if isinstance(parsed, dict) else None


def spf_lookups(spf):
    """DNS lookups an SPF record costs to evaluate.

    RFC 7208 caps this at 10; a record that exceeds it is a permerror at the
    receiver and provides no protection at all, however well-formed it looks.
    checkdmarc counts them, so record it rather than assuming compliance.
    """
    if not isinstance(spf, dict):
        return None
    n = spf.get("dns_lookups")
    return n if isinstance(n, int) else None


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
                    help="only the first N domains; for a pilot run")
    ap.add_argument("--reparse", action="store_true",
                    help="re-derive the table from the newest raw snapshot "
                         "without re-querying DNS. This is why the snapshot is "
                         "written before anything parses it: a classification "
                         "bug costs a second, not another full sweep.")
    args = ap.parse_args()

    dom = domains_from_frame()

    if args.reparse:
        import glob
        snaps = sorted(glob.glob(os.path.join(RAW, "checkdmarc_*.json")))
        if not snaps:
            sys.exit(f"no snapshot in {RAW}; run without --reparse first")
        with open(snaps[-1]) as fh:
            results = json.load(fh)
        today = os.path.basename(snaps[-1])[11:21]
        ns_label = "from-snapshot"
        print(f"==> re-parsing {os.path.basename(snaps[-1])} ({len(results)} domains)")
        return emit(results, dom, today, ns_label)

    try:
        from checkdmarc import check_domains
    except ImportError:
        sys.exit("checkdmarc is not installed. pip install checkdmarc")

    resolver, ns_label = working_resolver()
    print(f"==> resolver: {ns_label}")
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

    return emit(results, dom, today, ns_label)


def emit(results, dom, today, ns_label):
    """Turn raw checkdmarc output into the table. Split out of main() so
    --reparse can re-derive it from a snapshot without re-querying DNS.
    """
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
            "spf_qualifier": spf_qualifier(spf),
            "spf_dns_lookups": spf_lookups(spf),
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
