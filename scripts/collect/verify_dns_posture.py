"""Collection adapter: re-measure DNS posture by a second route, and disagree.

This exists because dns_posture.py cannot check itself. Every guard in that file
tests whether checkdmarc ANSWERED -- none of them test whether the answer is
right, and the failure that matters most here produces confident, well-formed,
uniformly wrong output. The 2026-08-08 sweep recorded `dnssec: false` for all
523 domains, wrote a clean CSV, printed a clean summary and passed every check
the project had. What was missing was not another assertion over the same
numbers. It was a second measurement that shares no code with the first.

So this queries the same facts through `dig` -- a different resolver library, a
different process, a different wire path -- and reports where the two disagree.
Agreement is not proof. Disagreement is proof of a problem, and that asymmetry
is the whole value.

WHAT IT COMPARES
  dmarc policy   `p` parsed out of the _dmarc TXT record found at the domain
                 itself. Deliberately NAIVE: it does not walk up to the
                 organizational domain. checkdmarc does, correctly, so the
                 expected disagreement is exactly the set of domains whose
                 record is inherited -- and that set is reported rather than
                 suppressed, because a domain appearing in it that should not
                 be is a real finding.
  dnssec         DNSKEY at the apex, plus the AD flag from a validating
                 resolver. Two signals, because they fail differently: a zone
                 can publish keys that do not chain to the root, and AD alone
                 cannot tell an unsigned zone from an unreachable one.

WHAT COUNTS AS A FAILURE
  A policy conflict is investigated, not simply failed. Both sides run through
  caching resolvers, so a domain that changed its policy inside the old TTL
  reads differently through each -- a fact about caches, not about the
  institution. Conflicts are therefore re-asked at the domain's own nameservers,
  and only a conflict where authoritative contradicts the MEASUREMENT fails.
  Failing on every conflict was the first design, and it would have failed this
  build while pointing at a correct number.
  A DNSSEC column that is uniform in either direction is a hard failure. All
  False was the original bug; all True would be a validating resolver lying to
  us just as completely, and is no more believable.
  Too few direct dig matches is a hard failure, because a probe that matches
  nothing reports zero conflicts and proves nothing.

FROZEN. Listed in FROZEN_COLLECTORS; never runs in a build.

Usage:  python scripts/collect/verify_dns_posture.py [--resolver 1.1.1.1]
"""

import argparse
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pandas as pd

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
POSTURE = os.path.join(REPO, "data", "institution_dns_posture.csv")
OUT = os.path.join(REPO, "data", "institution_dns_posture_verify.csv")

POLICY_RE = re.compile(r"\bp\s*=\s*(none|quarantine|reject)\b", re.I)
PROTECTED = ("quarantine", "reject")


def dig(args, timeout=20):
    """One dig invocation. Returns stdout, or '' on any failure.

    Empty output is ambiguous here -- no record, or no answer -- which is why
    nothing in this file infers `absent` from it. This script's job is to
    contradict the primary measurement, not to replace it.
    """
    try:
        r = subprocess.run(
            ["dig", "+time=3", "+tries=2"] + args, capture_output=True, text=True, timeout=timeout
        )
    except (subprocess.SubprocessError, OSError):
        return ""
    # dig writes ";; connection timed out; no servers could be reached" to
    # STDOUT, not stderr, even under +short. Returning it raw made
    # bool(dig(...)) true for every domain, so an unreachable resolver scored a
    # DNSKEY on all 620 zones and 21% agreement -- which is what the guards
    # below caught. Diagnostic lines are not answers.
    return "\n".join(ln for ln in r.stdout.splitlines() if not ln.startswith(";;"))


def authoritative_policy(domain):
    """The DMARC policy the domain's own nameservers serve, bypassing caches.

    Needed because a disagreement between two recursive resolvers does not say
    which one is wrong. Both sides cache, and a domain that changed its policy
    recently will read differently through different resolvers until the old TTL
    expires -- which is a fact about caches, not about the institution.

    parliament.gov.sl is the case that prompted this: its own nameservers serve
    `p=none`, while 1.1.1.1 and 8.8.8.8 were both still serving a stale
    `p=quarantine`. Without a tie-break the verifier would have failed the build
    and pointed at the correct measurement as the error.

    Returns None when the authoritative servers cannot be reached, which is a
    reason to leave the conflict standing rather than to resolve it either way.
    """
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        zone = ".".join(labels[i:])
        servers = [s for s in dig(["+short", "NS", zone]).split() if s.endswith(".")]
        if not servers:
            continue
        for s in servers:
            txt = dig(["+short", "TXT", f"_dmarc.{domain}", f"@{s}"])
            if "V=DMARC1" in txt.upper():
                m = POLICY_RE.search(txt)
                return m.group(1).lower() if m else None
    return None


def probe(domain, ns):
    at = f"@{ns}"
    txt = dig(["+short", "TXT", f"_dmarc.{domain}", at])
    dmarc = "V=DMARC1" in txt.upper()
    m = POLICY_RE.search(txt)
    dnskey = dig(["+short", "DNSKEY", domain, at]).strip()
    soa = dig(["+dnssec", "SOA", domain, at])
    ad = bool(re.search(r"^;; flags:[^;]*\bad\b", soa, re.M))
    return {
        "domain": domain,
        "dig_dmarc_found": dmarc,
        "dig_policy": m.group(1).lower() if m else None,
        "dig_dnskey": bool(dnskey),
        "dig_ad_flag": ad,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--resolver",
        default="1.1.1.1",
        help="a VALIDATING resolver, and deliberately not the one "
        "dns_posture.py chose. Sharing a resolver would let "
        "one broken network path satisfy both measurements.",
    )
    ap.add_argument("--workers", type=int, default=24)
    args = ap.parse_args()

    # Confirm the second route can actually resolve before measuring 600 domains
    # through it. 1.1.1.1 stopped answering from this host partway through a
    # session; without this probe the run produces a full table of nothing and
    # relies on the downstream guards to notice.
    if (
        "V=DMARC1"
        not in dig(["+short", "TXT", "_dmarc.parliament.uk", f"@{args.resolver}"]).upper()
    ):
        sys.exit(
            f"the verification resolver {args.resolver} does not answer. This "
            "script exists to disagree with the primary measurement, so it must "
            "reach a resolver the primary did not use -- pass --resolver with one "
            "that works rather than accepting a sweep nothing checked."
        )

    if not os.path.exists(POSTURE):
        sys.exit(f"no posture table at {POSTURE}; run dns_posture.py first")
    post = pd.read_csv(POSTURE)
    print(f"==> verifying {len(post):,} domains via dig @{args.resolver}")

    with ThreadPoolExecutor(args.workers) as ex:
        rows = list(ex.map(lambda d: probe(d, args.resolver), post.domain))
    v = pd.DataFrame(rows)
    m = post.merge(v, on="domain", how="left")
    m.to_csv(OUT, index=False)

    fail = 0

    # A comparison is only evidence if both sides actually measured something.
    # Every check below is scoped to dmarc_status == "ok", so a primary
    # measurement that reported "absent" for every domain would produce an empty
    # comparison set and a clean exit -- the verifier certifying the exact
    # catastrophe it exists to catch. Assert the two sides are non-degenerate
    # BEFORE comparing them.
    n_dig_found = int(m.dig_dmarc_found.fillna(False).astype(bool).sum())
    n_primary_ok = int((m.dmarc_status == "ok").sum())
    print(f"\n  primary found a record on {n_primary_ok}; dig found one on {n_dig_found}")
    if n_dig_found == 0:
        fail = 1
        print(
            "  FAIL: dig found no DMARC record anywhere. Every comparison below "
            "is over an empty set and proves nothing."
        )
    if n_primary_ok == 0:
        fail = 1
        print(
            "  FAIL: the primary measurement reports no valid DMARC record "
            "anywhere. That is a broken sweep, not a finding."
        )

    # ---- policy conflicts -------------------------------------------------
    both = m[(m.dmarc_status == "ok") & m.dig_dmarc_found & m.dig_policy.notna()]
    conflict = both[both.dmarc_policy != both.dig_policy]
    print(f"\n  both methods found a record: {len(both)}")
    print(f"  policy conflicts:             {len(conflict)}")
    if len(conflict):
        print("  conflicts, resolved against the domain's own nameservers:")
        for row in conflict.itertuples(index=False):
            auth = authoritative_policy(row.domain)
            if auth is None:
                fail = 1
                verdict = "UNRESOLVED -- authoritative servers unreachable"
            elif auth == row.dmarc_policy:
                verdict = "measurement correct; the dig resolver is serving a stale record"
            elif auth == row.dig_policy:
                fail = 1
                verdict = "FAIL -- the measurement is wrong, dig matches authoritative"
            else:
                fail = 1
                verdict = "FAIL -- authoritative agrees with neither"
            print(
                f"    {row.domain}: measured={row.dmarc_policy} "
                f"dig={row.dig_policy} authoritative={auth}"
            )
            print(f"      {verdict}")

    # Expected, and reported so it stays visible: checkdmarc walks up to the
    # organizational domain and this script does not.
    inherited = m[(m.dmarc_status == "ok") & ~m.dig_dmarc_found]
    print(
        f"  record inherited from parent: {len(inherited)} "
        "(expected; checkdmarc walks up, dig here does not)"
    )

    # A comparison over an empty set reports zero conflicts and proves nothing.
    # The first version of this file searched for "v=DMARC1" in an upper-cased
    # string, so dig never matched anything, every domain looked "inherited",
    # and the script printed "0 policy conflicts / ok" while comparing nothing
    # at all -- a verifier with the same disease as the bug it was written to
    # catch. Only a minority of domains legitimately inherit, so the naive probe
    # must find the large majority directly. If it does not, the probe is broken,
    # not the world.
    if len(inherited) > len(both):
        fail = 1
        print(
            f"  FAIL: dig matched a record on only {len(both)} domains while "
            f"{len(inherited)} appear to inherit. Inheritance is the rare "
            "case; this means the probe is not matching, and any comparison "
            "below it is vacuous."
        )

    # ---- dnssec -----------------------------------------------------------
    meas = m[m.dnssec_status.isin(["ok", "absent"])]
    if len(meas):
        agree = (meas.dnssec.astype(bool) == meas.dig_dnskey).mean()
        n_true = int(meas.dnssec.astype(bool).sum())
        print(f"\n  dnssec measured on {len(meas)}; signed: {n_true}")
        print(f"  agreement with dig DNSKEY:    {agree:.1%}")
        print(f"  dig AD flag set:              {int(meas.dig_ad_flag.sum())}")
        if n_true == 0 or n_true == len(meas):
            fail = 1
            print(
                "  FAIL: the DNSSEC column is uniform. All-False was the "
                "2026-08-08 bug and all-True is no more believable; neither "
                "is a measurement."
            )
        if agree < 0.90:
            fail = 1
            print(f"  FAIL: only {agree:.0%} agreement on DNSSEC between " "checkdmarc and dig.")
        # Agreement counts matching NEGATIVES too, so if dig resolved no DNSKEY
        # at all it still scores ~92% against a frame that is ~80% unsigned --
        # a pass earned entirely by both sides saying "no". The second route has
        # to have found something for its agreement to mean anything.
        n_dig_keys = int(meas.dig_dnskey.fillna(False).astype(bool).sum())
        print(f"  dig resolved a DNSKEY on:      {n_dig_keys}")
        if n_dig_keys == 0:
            fail = 1
            print(
                "  FAIL: dig resolved no DNSKEY on any domain, so the "
                "agreement figure above is agreement about nothing."
            )
    else:
        fail = 1
        print("\n  FAIL: no domain has a measured DNSSEC status.")

    print(f"\n  wrote {OUT}")
    if fail:
        sys.exit("\nVERIFICATION FAILED -- do not report these numbers.")
    print("  ok: the second route agrees with the first")


if __name__ == "__main__":
    main()
