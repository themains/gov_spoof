"""Collection adapter: email-authentication posture of national institutions.

Measures the PHISHING surface of every national institution in the frame --
legislature, head-of-state office, executive and highest court. Among EuRepoC
incidents carrying a coded initial-access technique, phishing (35.4%) and
exploitation of a public-facing application (34.8%) are the two leading entry
vectors and are level with each other -- 179 incidents against 176 -- while both
run more than three times the share attributable to stolen credentials (10.9%),
which is the only vector the rest of this project measures. A domain without an
enforcing DMARC policy can be spoofed, and spoofing is how phishing at
institutions usually starts.

Only 14.8% of incidents carry that coding at all, and the political-target
subset is 11 incidents, so none of the above is a claim about legislatures
specifically. It is the reason this surface is worth measuring, not a result.

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

EVERY measured column carries one. The 2026-08-08 sweep recorded `dnssec: false`
for all 523 domains and the README reported "zero of 523" as a finding. It was
not one: 119 of those zones are signed, riksdagen.se and congress.gov and ft.dk
among them. `dnssec` was the one column that came back as a bare bool, so "not
signed" and "we could not ask" had the same value and no guard could tell them
apart. The mechanism is in dnssec_nameservers() below. The lesson is the one
this file already knew and applied everywhere else: a column without a status is
a column that can lie.

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
OUT = os.path.join(REPO, "data", "institution_dns_posture.csv")

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
# The SYSTEM resolver is tried FIRST, then public ones.
#
# The reverse order looked more principled -- pinned resolvers make a
# measurement reproducible rather than dependent on the local network -- and it
# produced a run where 498 of 523 lookups failed. 1.1.1.1 answered the startup
# probe, served exactly one batch of 25, then became unreachable, and every
# subsequent batch died on "no nameservers". A pinned resolver is only
# reproducible if it stays up; the system resolver here answers in 0.02s and has
# never dropped. Whichever is used is recorded in every output row.
PREFERRED_NAMESERVERS = ["system", "1.1.1.1", "8.8.8.8", "9.9.9.9"]
PROBE = "_dmarc.parliament.uk"

# The DNSSEC probe is a DIFFERENT QUESTION asked over a DIFFERENT TRANSPORT, and
# it must be both. See dnssec_nameservers(). riksdagen.se is signed and has been
# for years; probing an unsigned zone cannot separate "no DNSSEC here" from
# "this nameserver will not answer me".
DNSSEC_PROBE = "riksdagen.se"

# A run where too many lookups fail is not a measurement, and must not leave
# behind a file that looks like one. The 498-failure run wrote a perfectly
# well-formed CSV that would have passed every downstream check while showing
# 95% of the world's institutions publishing no DMARC.
MAX_FAILURE_RATE = 0.20


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
        try:
            if ns == "system":
                r = dns.resolver.Resolver()
            else:
                r = dns.resolver.Resolver(configure=False)
                r.nameservers, r.timeout, r.lifetime = [ns], 3, 3
            r.resolve(PROBE, "TXT")
            return r, ns
        except Exception:  # noqa: BLE001 - unreachable is the only thing that matters
            continue
    sys.exit("no working DNS resolver")


def dnssec_nameservers():
    """Return (nameserver_list, label) that answers DNSKEY over TCP, or (None, None).

    DNSSEC needs its own nameserver because checkdmarc does not route DNSSEC
    through the resolver object. check_domains(..., resolver=r) forwards r to
    the DMARC, SPF, SOA, NS and MX lookups, but its DNSSEC line reads

        test_dnssec(domain, nameservers=nameservers, timeout=timeout)

    and test_dnssec takes no resolver at all. With `nameservers` unset it falls
    back to dns.resolver.Resolver().nameservers, which is whatever
    /etc/resolv.conf says, no matter what the caller so carefully selected.

    It needs its own PROBE because checkdmarc's DNSKEY lookups go over
    dns.query.tcp, and the UDP probe in working_resolver() does not exercise TCP
    at all. That gap is what produced the "zero of 523" finding. The machine
    that ran the 2026-08-08 sweep had 192.0.2.42 in /etc/resolv.conf -- a
    TEST-NET-1 address, which should be unreachable -- and the network
    intercepted UDP/53 to it while dropping TCP/53. So the UDP probe passed, the
    resolver looked healthy, every DMARC lookup succeeded, and every DNSKEY
    query timed out into `false`. MAX_FAILURE_RATE read dmarc_status, saw a
    clean run, and let a fabricated column through.

    Probing the transport the measurement actually uses is the general form of
    the rule the rest of this file follows. A probe that does not exercise what
    the measurement exercises is not a probe.

    Returning (None, None) is a legitimate outcome and is NOT a licence to
    record False: emit() turns it into dnssec_status='lookup_failed'.
    """
    import dns.resolver
    from checkdmarc.dnssec import get_dnskey

    for ns in PREFERRED_NAMESERVERS:
        try:
            nslist = (dns.resolver.Resolver().nameservers if ns == "system"
                      else [ns])
            nslist = [str(x) for x in nslist]
            if not nslist:
                continue
            if get_dnskey(DNSSEC_PROBE, nameservers=nslist, timeout=5):
                return nslist, ns
        except Exception:  # noqa: BLE001 - unreachable is the only thing that matters
            continue
    return None, None


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


def effective_policy(dmarc, domain):
    """The DMARC policy a receiver actually applies to mail from `domain`.

    Not always the `p` tag. RFC 7489 6.6.3: a receiver that finds no record at
    the domain itself walks up to the organizational domain, and where that
    parent record carries `sp`, `sp` is what governs the subdomain. checkdmarc
    already does the walk and reports where it landed, so an inherited record is
    one whose `location` is not the domain queried.

    33 domains in the 2026-08-08 sweep inherit a parent record, and four of them
    -- governo.gov.ao, al.gov.mo, president.gov.mt, pr.gov -- sit under a parent
    publishing a strict `p` with `sp=none`. Read off `p` they look defended.
    Read the way mail is actually filtered, nothing blocks a forgery of them.

    `p` is kept alongside this in the output, because "what the record says" and
    "what a receiver does" are both worth being able to see.
    """
    if not isinstance(dmarc, dict) or not dmarc.get("valid"):
        return None
    tags = dmarc.get("tags") or {}
    p = (tags.get("p") or {}).get("value")
    sp = (tags.get("sp") or {}).get("value")
    location = dmarc.get("location")
    if location and location != domain and sp:
        return sp
    return p


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
    """One row per institution domain, from the Wikidata-derived frame.

    An institution may publish several domains -- the Folketing has four, one of
    them Faroese and one Greenlandic -- and each is a separate surface to
    secure, so each is measured. Aggregating to the institution or the country
    is an analysis decision made later, not a collection one made here.

    Legislatures with no published website stay out of the sweep but remain in
    the frame with a null domain, so the denominator of "how many could be
    measured" is not quietly reduced to "how many were".
    """
    frame = pd.read_csv(os.path.join(REPO, "data", "institution_domains.csv"))
    have = frame[frame.domain.notna()].copy()
    return (
        have[["domain", "country", "cc3", "branch", "body", "body_qid", "sovereign"]]
        .drop_duplicates("domain")
        .sort_values(["country", "domain"])
        .reset_index(drop=True)
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=None,
                    help="only the first N domains; for a pilot run")
    ap.add_argument("--verbose", action="store_true",
                    help="attach a handler to checkdmarc's own logger. It "
                         "reports every failed lookup at DEBUG, including the "
                         "'DNSSEC query error' that fired 523 times during the "
                         "2026-08-08 sweep with nothing listening. Progress "
                         "narration below stays on stdout; this is for when a "
                         "column comes back uniform and you need to know why.")
    ap.add_argument("--reparse", action="store_true",
                    help="re-derive the table from the newest raw snapshot "
                         "without re-querying DNS. This is why the snapshot is "
                         "written before anything parses it: a classification "
                         "bug costs a second, not another full sweep.")
    args = ap.parse_args()

    if args.verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG, format="  [%(name)s] %(message)s")

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
    dnssec_ns, dnssec_label = dnssec_nameservers()
    print(f"==> resolver: {ns_label}")
    if dnssec_ns:
        print(f"==> dnssec nameserver: {dnssec_label} (answers DNSKEY over TCP)")
    else:
        print("==> dnssec: NO nameserver answers DNSKEY over TCP.")
        print("    Every DNSSEC result this run will be recorded as")
        print("    lookup_failed, not as 'unsigned'. Fix the network path")
        print("    before reporting anything about DNSSEC.")
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
    # The snapshot is written AFTER EVERY BATCH and reloaded on start, so a
    # killed run resumes instead of starting over. Writing it only at the end --
    # which is what this did first -- lost two multi-hour sweeps: the design
    # intent was snapshot-before-parse, but scoped to the whole run rather than
    # each batch, which protects against a parser bug and not against anything
    # that stops the process.
    snap_path = os.path.join(RAW, f"checkdmarc_{today}.json")
    results = []
    if os.path.exists(snap_path):
        with open(snap_path) as fh:
            results = json.load(fh)
        print(f"  resuming: {len(results)} domains already in today's snapshot")

    done = {r.get("domain") for r in results}
    domains = [d for d in dom.domain if d not in done]
    if not domains:
        print("  nothing left to fetch")
    CHUNK = 25

    def add(r, served_by):
        """Record a batch, stamping which nameserver answered its DNSKEY queries.

        Stamped per row rather than per run so --reparse can tell, from the
        snapshot alone, whether DNSSEC was measurable at the time. A snapshot
        written before this column existed has no stamp, and emit() reads that
        absence as lookup_failed -- which is exactly what the 2026-08-08
        snapshot deserves.
        """
        for row in ([r] if isinstance(r, dict) else r):
            row["dnssec_nameserver"] = served_by
            results.append(row)

    for i in range(0, len(domains), CHUNK):
        batch = domains[i:i + CHUNK]
        try:
            # timeout/retries left at checkdmarc's defaults. Raising them to
            # 5.0/1 pushed 50 domains past ten minutes, and a longer timeout
            # does not buy much here: a resolver that has not answered in two
            # seconds is recorded as lookup_failed, which is the honest outcome
            # anyway. Speed matters because the sweep is meant to be repeatable.
            #
            # BOTH resolver and nameservers are passed. checkdmarc's query_dns
            # ignores `nameservers` whenever a resolver object is supplied, so
            # the resolver still governs DMARC, SPF, SOA, NS and MX. The one
            # place `nameservers` is read is test_dnssec, which accepts no
            # resolver -- so this argument exists solely to keep the DNSSEC
            # column off /etc/resolv.conf.
            r = check_domains(batch, skip_tls=True, resolver=resolver,
                              nameservers=dnssec_ns)
            add(r, dnssec_label)
        except Exception as exc:  # noqa: BLE001 - one bad batch must not end the run
            # Re-probe before writing the batch off. A resolver that worked at
            # startup can die mid-run, and treating that as 25 domains with no
            # DMARC would be a fabricated finding.
            print(f"  batch {i}-{i + len(batch)} failed ({type(exc).__name__}); re-probing")
            try:
                resolver, ns_label = working_resolver()
                dnssec_ns, dnssec_label = dnssec_nameservers()
                print(f"  resolver now: {ns_label}; retrying batch")
                r = check_domains(batch, skip_tls=True, resolver=resolver,
                                  nameservers=dnssec_ns)
                add(r, dnssec_label)
                print(f"  {min(i + CHUNK, len(domains)):>4}/{len(domains)}", flush=True)
                continue
            except Exception as exc2:  # noqa: BLE001
                print(f"  retry also failed: {exc2}")
                for d in batch:
                    results.append({"domain": d, "dnssec_nameserver": None,
                                    "dmarc": {"valid": False,
                                              "error": f"batch error: {exc2}"}})
        with open(snap_path, "w") as fh:
            json.dump(results, fh, indent=1, default=str)
        print(f"  {len(results):>4}/{len(dom)} (snapshot saved)", flush=True)

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

        # A DNSKEY query that was never asked is not a zone that is unsigned.
        # `dnssec` is a bare bool, so the stamp is the only thing that separates
        # them; no stamp means no measurement, whatever the bool happens to say.
        served_by = res.get("dnssec_nameserver")
        if d_status == "nxdomain":
            dnssec_status = "nxdomain"
            dnssec = None
        elif not served_by:
            dnssec_status = "lookup_failed"
            dnssec = None
        else:
            dnssec = bool(res.get("dnssec"))
            dnssec_status = "ok" if dnssec else "absent"

        rows.append({
            "domain": res.get("domain"),
            "dmarc_status": d_status,
            "dmarc_policy": policy,
            "dmarc_effective_policy": effective_policy(dmarc, res.get("domain")),
            "dmarc_error": d_err,
            "spf_status": s_status,
            "spf_qualifier": spf_qualifier(spf),
            "spf_dns_lookups": spf_lookups(spf),
            "spf_error": s_err,
            "mta_sts": status_of(res.get("mta_sts"))[0],
            "dnssec": dnssec,
            "dnssec_status": dnssec_status,
            "dnssec_resolver": served_by,
            "checked_date": today,
            "resolver": ns_label,
            "source_id": "dns_posture",
        })

    out = pd.DataFrame(rows).merge(dom, on="domain", how="left")

    # Refuse to write a broken run. A sweep where a fifth of lookups failed is
    # not a measurement of anything, and the file it would produce is
    # indistinguishable from a real one at every downstream check -- correctly
    # typed, correctly named, and quietly claiming that most of the world's
    # institutions publish no DMARC. Exiting non-zero without writing is the
    # only behaviour that cannot be mistaken for a result.
    # Checked PER COLUMN. The single-column version of this guard read
    # dmarc_status alone and certified the 2026-08-08 run as clean while the
    # DNSSEC column was 100% unmeasured: a healthy DMARC sweep says nothing
    # about whether any other lookup got an answer. Each column now has to
    # stand on its own.
    for col in ("dmarc_status", "spf_status", "dnssec_status"):
        failed = int((out[col] == "lookup_failed").sum())
        fail_rate = failed / len(out)
        if fail_rate > MAX_FAILURE_RATE:
            sys.exit(
                f"ABORTED: {fail_rate:.0%} of {col.split('_')[0].upper()} lookups "
                f"failed ({failed} of {len(out)}), above the "
                f"{MAX_FAILURE_RATE:.0%} ceiling. This is a broken run, not a "
                "finding -- nothing written. Check resolver reachability and retry."
            )

    out.to_csv(OUT, index=False)

    n = len(out)
    print("\n  dmarc: " + ", ".join(
        f"{k} {v}" for k, v in out.dmarc_status.value_counts().items()))
    print("  effective policy among valid: " + ", ".join(
        f"{k} {v}" for k, v in
        out.dmarc_effective_policy.value_counts(dropna=False).items()))
    print("  dnssec: " + ", ".join(
        f"{k} {v}" for k, v in out.dnssec_status.value_counts().items()))

    for col, name, absent_means in (
        ("dmarc_status", "DMARC", "no DMARC"),
        ("dnssec_status", "DNSSEC", "unsigned"),
    ):
        failed = int((out[col] == "lookup_failed").sum())
        print(f"\n  {failed} of {n} {name} lookups FAILED and are recorded as")
        print(f"  missing, not as '{absent_means}'. Treat them as missing downstream.")
    print(f"\n  wrote {OUT}")


if __name__ == "__main__":
    main()
