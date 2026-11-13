"""Every number in the README comes from here.

This stage did not exist for the first three months of the project, and its
absence is what let a fabricated column reach the front page. `dnssec: false`
for all 523 domains was written up as "DNSSEC: zero of 523. Not one national
institution has it enabled" -- a sentence nobody could have typed while looking
at a generated table with riksdagen.se and congress.gov in it. Numbers computed
by hand at a REPL and pasted into prose cannot be re-derived, cannot be
regression-tested, and cannot disagree with the person pasting them.

So: one script, one definition of each quantity, one place to fix a definition.
Writes tables/*.md for reading and tables/headline.json for `make check-readme`,
which fails the build when the prose and the tables drift apart. That gate is
the point of the file as much as the tables are.

Reads only frozen inputs. Never touches the network.

Usage:  python analysis/posture_tables.py
"""

import json
import os

import pandas as pd

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
DATA = os.path.join(REPO, "data")
TABLES = os.path.join(REPO, "tables")

# A domain is EXCLUDED when we could not measure it, and only then. `nxdomain`
# means Wikidata lists a site that has gone away, which is a fact about the
# frame; `lookup_failed` means we could not ask. Neither is a posture finding,
# and folding either into "publishes nothing" is the single easiest way to
# manufacture a result in this area.
MEASURED = ("ok", "absent", "invalid")

# Verdicts from data/domain_control_review.csv that take a domain out of the
# posture measurement, because the row does not describe the institution it is
# filed under. Each is hand-reviewed with its evidence recorded there.
#
#   lost           the institution held the domain and no longer does. apn-dz.org
#                  went Assemblee Populaire Nationale -> "This website is for
#                  sale!" -> a detective agency in Ichikawa, and it publishes a
#                  valid DMARC record, so counting it credited Algeria's
#                  parliament with the detective agency's good hygiene.
#   never_theirs   a P856 value that was never the institution's at all.
#   parallel_body  a real organization, but not the state institution being
#                  enumerated, and the state one is already in the frame.
#   defunct_body   the institution itself no longer exists.
#
# `unresolved` and `keep` stay IN. An unreachable homepage is not evidence of
# anything: WAFs refuse non-browser agents and 124 of 525 domains returned no
# response at all.
NOT_THE_INSTITUTION = ("lost", "never_theirs", "parallel_body", "defunct_body")

# Blocks a forgery at the receiver. `none` does not: it asks for reports and
# tells the receiver to deliver the mail anyway.
PROTECTED = ("quarantine", "reject")

MANDATE_CC3 = ["USA", "GBR", "NLD", "NZL", "DNK"]
BRANCH_ORDER = ["judiciary", "head_of_state_office", "legislature", "executive"]
BRANCH_LABEL = {
    "judiciary": "Supreme courts",
    "head_of_state_office": "Heads of state",
    "legislature": "Legislatures",
    "executive": "Executives / governments",
}

POLITICAL = ["Legislative", "Political parties", "Election infrastructure / related systems"]


def status(row):
    """The one definition of a domain's DMARC posture. Everything routes here.

    Returns 'reject', 'quarantine', 'none', 'absent' or 'invalid'.

    Uses dmarc_effective_policy, not dmarc_policy, because those differ for the
    domains that inherit a parent record with a weaker `sp` -- and what protects
    a person reading their mail is what the receiver applies, not what the
    record's own `p` tag says. Keeping this in a function rather than at each
    call site is deliberate: the two were confused once already, and a single
    definition is the only thing that stops it happening twice.
    """
    if row.dmarc_status in ("absent", "invalid"):
        return row.dmarc_status
    return row.dmarc_effective_policy


def md_table(df, headers):
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    for r in df.itertuples(index=False):
        lines.append("| " + " | ".join(str(x) for x in r) + " |")
    return "\n".join(lines) + "\n"


def _n(df, technique):
    """Incident count for one MITRE technique."""
    return int(df.loc[df.technique == technique, "incidents"].iloc[0])


def write(name, title, body):
    path = os.path.join(TABLES, name)
    with open(path, "w") as fh:
        fh.write(f"# {title}\n\n{body}")
    print(f"  wrote tables/{name}")


def main():
    os.makedirs(TABLES, exist_ok=True)
    post = pd.read_csv(os.path.join(DATA, "institution_dns_posture.csv"))
    H = {}

    # ---- 1. what was measured -------------------------------------------
    n_swept = len(post)

    # Drop rows that do not describe the institution they are filed under,
    # BEFORE anything is counted. Doing this at the top rather than per table is
    # the point: the same exclusion has to reach the headline, the branch table
    # and the mandate comparison, and a filter applied at three call sites is a
    # filter that will eventually be applied at two.
    review = pd.read_csv(os.path.join(DATA, "domain_control_review.csv"))
    drop = review[review.verdict.isin(NOT_THE_INSTITUTION)]
    post = post[~post.domain.isin(drop.domain)].copy()

    # Where each domain came from. Everything below is computed twice, on the
    # Wikidata-sourced domains alone and on the expanded frame, because the
    # expansion is not a random top-up: resolution succeeds where a country is
    # well documented, which is the same gradient as institutional capacity.
    # Reporting only the expanded number would hide that; reporting only the
    # original would throw away the finding that the additions are worse.
    _frame = pd.read_csv(os.path.join(DATA, "institution_domains.csv"))
    _src = _frame[_frame.domain.notna()].drop_duplicates("domain").set_index("domain")
    post["domain_source"] = post.domain.map(_src.domain_source).fillna("wikidata_p856")

    m = post[post.dmarc_status.isin(MEASURED)].copy()
    m["posture"] = m.apply(status, axis=1)
    m["unprotected"] = ~m.posture.isin(PROTECTED)
    n_measured = len(m)

    excl = (
        post[~post.dmarc_status.isin(MEASURED)]
        .dmarc_status.value_counts()
        .rename_axis("reason")
        .reset_index(name="domains")
    )
    # Jurisdictions counted on the MEASURED domains, not on the frame. The frame
    # reaches more countries than the sweep does, because a country can be in it
    # with a null domain -- an institution that publishes no website is still an
    # institution. Quoting the frame's count beside the sweep's domain count
    # would credit the measurement with reach it does not have.
    frame = pd.read_csv(os.path.join(DATA, "institution_domains.csv"))
    H.update(
        n_swept=n_swept,
        n_measured=n_measured,
        n_excluded=n_swept - n_measured,
        n_jurisdictions=int(m.cc3.nunique()),
        n_frame_jurisdictions=int(frame.cc3.nunique()),
    )
    write(
        "exclusions.md",
        "Sweep accounting",
        f"{n_swept} domains swept, {len(drop)} dropped as not the institution's, "
        f"{n_measured} measured.\n\n" + md_table(excl, ["reason", "domains"]),
    )

    # ---- 1b. domain control ---------------------------------------------
    vc = review.verdict.value_counts().rename_axis("verdict").reset_index(name="domains")
    lost = review[review.verdict == "lost"]
    H.update(
        n_domain_control_dropped=len(drop),
        n_lost=int((review.verdict == "lost").sum()),
        n_never_theirs=int((review.verdict == "never_theirs").sum()),
        n_defunct_body=int((review.verdict == "defunct_body").sum()),
    )
    write(
        "domain_control.md",
        "Does the institution still control the domain?",
        "Every domain on a generic TLD, plus every domain whose homepage tripped "
        "a content flag, reviewed by hand. Evidence for each verdict is in "
        "`data/domain_control_review.csv`.\n\n"
        + md_table(vc, ["verdict", "domains"])
        + "\nDomains the institution held and lost:\n\n"
        + md_table(lost[["domain", "country", "branch"]], ["domain", "country", "branch"])
        + "\n`unresolved` and `keep` stay in the measurement. An unreachable "
        "homepage is not evidence of a lost domain.\n",
    )

    # ---- 2. the headline -------------------------------------------------
    order = ["reject", "quarantine", "none", "absent", "invalid"]
    lab = {
        "reject": "`p=reject` — blocks forged mail",
        "quarantine": "`p=quarantine` — sends it to spam",
        "none": "`p=none` — monitors, blocks nothing",
        "absent": "no DMARC record at all",
        "invalid": "record published but malformed",
    }
    pol = pd.DataFrame(
        {
            "DMARC policy": [lab[k] for k in order],
            "domains": [int((m.posture == k).sum()) for k in order],
            "share": [f"{(m.posture == k).mean():.1%}" for k in order],
        }
    )
    n_unprot = int(m.unprotected.sum())
    H.update(
        n_unprotected=n_unprot,
        pct_unprotected=f"{m.unprotected.mean():.0%}",
        pct_reject=f"{(m.posture == 'reject').mean():.1%}",
        pct_quarantine=f"{(m.posture == 'quarantine').mean():.1%}",
        pct_none=f"{(m.posture == 'none').mean():.1%}",
        pct_absent=f"{(m.posture == 'absent').mean():.1%}",
        pct_invalid=f"{(m.posture == 'invalid').mean():.1%}",
    )

    # Robustness: an institution may publish several domains -- the Folketing
    # has four -- so a domain-level share could in principle be carried by a few
    # institutions with many weakly-configured aliases. Collapse to the
    # institution, counting it unprotected only when NONE of its domains is
    # protected, and see whether the number moves.
    inst = m.groupby("body_qid").unprotected.all()
    H.update(n_institutions=len(inst), pct_unprotected_institution=f"{inst.mean():.1%}")
    write(
        "dmarc_policy.md",
        "DMARC policy",
        f"Share of {n_measured} measured domains.\n\n"
        + md_table(pol, ["DMARC policy", "domains", "share"])
        + f"\nUnprotected (`none`, absent or malformed): {n_unprot} of "
        f"{n_measured} = {m.unprotected.mean():.1%}\n"
        f"\nCollapsed to the institution, counting one unprotected only when "
        f"no domain of it is protected: {int(inst.sum())} of {len(inst)} = "
        f"{inst.mean():.1%}\n",
    )

    # ---- 2b. what the expansion added, and how it differs ----------------
    wiki = m[m.domain_source == "wikidata_p856"]
    res = m[m.domain_source == "resolved"]
    sites = pd.read_csv(os.path.join(DATA, "institution_sites_resolved.csv"))
    srev = pd.read_csv(os.path.join(DATA, "institution_sites_review.csv"))
    n_target = int((sites.decision != "not_applicable").sum())
    # Institutions, not candidate evaluations. srev has one row per candidate,
    # and 17 institutions had a first candidate rejected before a later one was
    # accepted -- so counting rows made the outcome column sum to 218 against a
    # denominator of 172. An institution is accepted if ANY of its candidates
    # was, rejected only if it has candidates and none was accepted.
    accepted_ids = set(srev.loc[srev.verdict == "accept", "body_qid"].dropna())
    rejected_ids = set(srev.loc[srev.verdict == "reject", "body_qid"].dropna()) - accepted_ids
    n_acc = len(accepted_ids)
    n_rej = len(rejected_ids)
    H.update(
        n_resolved=len(res),
        pct_unprotected_resolved=f"{res.unprotected.mean():.1%}",
        pct_unprotected_wikidata=f"{wiki.unprotected.mean():.1%}",
        n_resolution_target=n_target,
        n_resolution_na=int((sites.decision == "not_applicable").sum()),
        n_resolution_accepted=n_acc,
        n_resolution_rejected=n_rej,
        # The residual is what is STILL missing after both passes, not the
        # first pass's miss count. Quoting the intermediate figure would
        # overstate how much is left and understate what the second pass did.
        n_resolution_unresolved=n_target - n_acc - n_rej,
    )
    write(
        "resolution.md",
        "Websites resolved outside Wikidata",
        f"{H['n_resolution_target']} live institutions carried no website in Wikidata. "
        f"A further {H['n_resolution_na']} are recorded as not applicable: offices held "
        "by a person, usually a crown shared between realms, and bodies of states that "
        "no longer exist.\n\n"
        "Three passes. The first reads the Wikipedia infobox `website` field. The second, "
        "for articles without one, takes the external links, keeps only hosts on that "
        "country's own ccTLD, and ranks them by whether the hostname names the branch. "
        "The third is a web search for what remains. All three produce candidates and "
        "none produces a decision: every candidate is then fetched, and the page that "
        "comes back is what decides it.\n\n"
        + md_table(
            pd.DataFrame(
                {
                    "outcome": [
                        "accepted into the frame",
                        "rejected on review",
                        "still unresolved",
                        "not applicable",
                    ],
                    "institutions": [
                        n_acc,
                        H["n_resolution_rejected"],
                        n_target - n_acc - n_rej,
                        H["n_resolution_na"],
                    ],
                }
            ),
            ["outcome", "institutions"],
        )
        + "\nEvery accept and every reject carries the page title that decided it in "
        "`data/institution_sites_review.csv`. Nothing is accepted automatically: a "
        "matching country code confirms the country and says nothing about the "
        "institution, which is how a first draft of this offered Guatemala's Ministry "
        "of Agriculture as its Council of Ministers.\n\n"
        "**The additions are worse defended than the frame they joined.**\n\n"
        + md_table(
            pd.DataFrame(
                {
                    "source": ["Wikidata `P856`", "resolved and hand-confirmed"],
                    "domains": [len(wiki), len(res)],
                    "unprotected": [
                        f"{wiki.unprotected.mean():.1%}",
                        f"{res.unprotected.mean():.1%}",
                    ],
                }
            ),
            ["source", "domains", "unprotected"],
        )
        + "\nAn institution whose website nobody recorded is an institution with less "
        "administrative capacity, and it defends its mail worse. Every figure on this "
        "page is therefore a lower bound: the institutions still missing from the frame "
        "are, on this evidence, the weakest ones.\n",
    )

    # ---- 3. branch, with and without holding the country fixed -----------
    br = m.groupby("branch").agg(
        domains=("domain", "size"),
        countries=("cc3", "nunique"),
        unprotected=("unprotected", "mean"),
    )
    br = br.reindex(BRANCH_ORDER)
    btab = pd.DataFrame(
        {
            "branch": [BRANCH_LABEL[b] for b in br.index],
            "domains": br.domains.values,
            "countries": br.countries.values,
            "unprotected": [f"{x:.1%}" for x in br.unprotected.values],
        }
    )
    for b in BRANCH_ORDER:
        H[f"pct_unprotected_{b}"] = f"{br.loc[b, 'unprotected']:.1%}"
        H[f"n_countries_{b}"] = int(br.loc[b, "countries"])
        # Exported so the provenance gate covers the branch table's first
        # column. It did not, and the README shipped 118 Supreme Court domains
        # against a generated 116 while check-readme reported success.
        H[f"n_domains_{b}"] = int(br.loc[b, "domains"])

    # The raw column above compares branches measured in DIFFERENT sets of
    # countries: the judiciary appears in far fewer than the legislature. Adding
    # country fixed effects asks the within-country question instead -- among
    # the institutions of one country, does the branch predict posture? Standard
    # errors clustered by country, since that is the unit the fixed effect and
    # the sampling both run on.
    # What the country-fixed-effects contrast is actually identified off. A
    # country contributing one branch is absorbed entirely by its own fixed
    # effect and tells the contrast nothing; a country with two or more is what
    # carries it. This is NOT the 37 countries that happen to have all four
    # measured -- that subset is only the model-free cross-check, and quoting it
    # alone makes the estimate look like it rests on a quarter of the data it
    # actually uses.
    per_country = m.groupby("cc3").branch.nunique()
    contributing = per_country[per_country >= 2].index
    H.update(
        n_countries_fe=int(len(contributing)),
        n_domains_fe=int(m.cc3.isin(contributing).sum()),
    )

    import statsmodels.formula.api as smf

    d = m.copy()
    d["y"] = d.unprotected.astype(int)
    fe = smf.ols('y ~ C(branch, Treatment("judiciary")) + C(cc3)', data=d).fit(
        cov_type="cluster", cov_kwds={"groups": d.cc3}
    )
    raw = smf.ols('y ~ C(branch, Treatment("judiciary"))', data=d).fit(
        cov_type="cluster", cov_kwds={"groups": d.cc3}
    )

    def contrast(fit, branch):
        key = [i for i in fit.params.index if branch in i][0]
        return fit.params[key], fit.bse[key]

    rows = []
    for b in ["head_of_state_office", "legislature", "executive"]:
        c0, s0 = contrast(raw, b)
        c1, s1 = contrast(fe, b)
        rows.append(
            {
                "contrast": f"{BRANCH_LABEL[b]} − Supreme courts",
                "no country FE": f"{100 * c0:+.1f} ({100 * s0:.1f})",
                "country FE": f"{100 * c1:+.1f} ({100 * s1:.1f})",
            }
        )
        H[f"fe_{b}"] = f"{100 * c1:+.1f}"
        H[f"fe_se_{b}"] = f"{100 * s1:.1f}"
        H[f"raw_{b}"] = f"{100 * c0:+.1f}"
        H[f"raw_se_{b}"] = f"{100 * s0:.1f}"

    # A second cut on the same question that does not lean on a linear model:
    # keep only countries where all four branches were measured, so every branch
    # is scored on an identical set of countries.
    full = m.groupby("cc3").branch.nunique()
    sub = m[m.cc3.isin(full[full == 4].index)]
    subtab = (
        sub.groupby("branch").unprotected.mean().reindex(BRANCH_ORDER).map(lambda x: f"{x:.1%}")
    )
    H.update(n_countries_all_four=int(sub.cc3.nunique()))
    for b in BRANCH_ORDER:
        H[f"allfour_{b}"] = subtab[b]

    write(
        "branch.md",
        "Posture by branch",
        md_table(btab, ["branch", "domains", "countries", "unprotected"])
        + f"\n\nThe country-fixed-effects contrast below is identified off the "
        f"{H['n_countries_fe']} countries with at least two branches measured, "
        f"covering {H['n_domains_fe']} of the {n_measured} domains. A country "
        "with only one branch is absorbed by its own fixed effect and "
        "contributes nothing to it.\n" + "\n\nDifference in unprotected share, percentage points "
        "(clustered SE in parentheses):\n\n"
        + md_table(pd.DataFrame(rows), ["contrast", "no country FE", "country FE"])
        + f"\n\nRestricted to the {sub.cc3.nunique()} countries where all four "
        "branches were measured, so every branch is scored on the same "
        "countries:\n\n"
        + md_table(
            subtab.rename("unprotected")
            .reset_index()
            .assign(branch=lambda x: x.branch.map(BRANCH_LABEL)),
            ["branch", "unprotected"],
        ),
    )

    # ---- 4. DNSSEC -------------------------------------------------------
    ds = post.dnssec_status.value_counts().rename_axis("status").reset_index(name="domains")
    dm = post[post.dnssec_status.isin(["ok", "absent"])]
    n_signed = int((dm.dnssec_status == "ok").sum())
    H.update(
        n_dnssec_signed=n_signed,
        n_dnssec_measured=len(dm),
        pct_dnssec=f"{n_signed / len(dm):.0%}" if len(dm) else "n/a",
    )
    write(
        "dnssec.md",
        "DNSSEC",
        f"{n_signed} of {len(dm)} measured zones are signed "
        f"({n_signed / len(dm):.1%}).\n\n"
        + md_table(ds, ["status", "domains"])
        + "\n`lookup_failed` means no nameserver answered a DNSKEY query over "
        "TCP. It is not evidence of an unsigned zone.\n",
    )

    # ---- 5. SPF ----------------------------------------------------------
    spf = (
        m.spf_qualifier.fillna("(no SPF record)")
        .value_counts()
        .rename_axis("SPF all-qualifier")
        .reset_index(name="domains")
    )
    n_hardfail = int((m.spf_qualifier == "fail").sum())
    # The number that carries the argument: institutions that configured SPF
    # strictly and still cannot stop a forgery of their From: address, because
    # SPF authenticates the envelope sender and receivers do not align it to the
    # header a person reads.
    n_spf_no_dmarc = int(((m.spf_qualifier == "fail") & m.unprotected).sum())
    H.update(n_spf_hardfail=n_hardfail, n_spf_hardfail_no_dmarc=n_spf_no_dmarc)
    write(
        "spf.md",
        "SPF",
        md_table(spf, ["SPF all-qualifier", "domains"])
        + f"\n{n_hardfail} domains publish a hard-fail (`-all`) policy.\n"
        f"\nOf those, {n_spf_no_dmarc} have no effective DMARC policy: "
        "strict SPF, and nothing stopping a forged `From:` address.\n",
    )

    # ---- 6. mandates -----------------------------------------------------
    mand = m[m.cc3.isin(MANDATE_CC3)]
    other = m[~m.cc3.isin(MANDATE_CC3)]
    H.update(
        n_mandate_domains=len(mand),
        pct_mandate_reject=f"{(mand.posture == 'reject').mean():.1%}",
        pct_other_reject=f"{(other.posture == 'reject').mean():.1%}",
    )
    write(
        "mandates.md",
        "Countries mandating DMARC on government domains",
        f"{(mand.posture == 'reject').mean():.1%} of {len(mand)} domains in "
        f"{', '.join(sorted(mand.cc3.unique()))} reach `p=reject`, against "
        f"{(other.posture == 'reject').mean():.1%} of {len(other)} elsewhere.\n\n"
        + md_table(
            mand[["domain", "cc3", "branch", "posture"]].sort_values("cc3"),
            ["domain", "cc3", "branch", "posture"],
        ),
    )

    # ---- 7. how intrusions start ----------------------------------------
    # Reads the COMMITTED aggregate, not data/raw/. The raw EuRepoC release is
    # gitignored (CC-BY-NC, and regenerable from its DOI), so a script that
    # reads it crashes on a clean checkout -- which is every CI run and every
    # reader who clones the repo. The aggregate carries the counts this page
    # quotes and nothing row-level.
    ia_all = pd.read_csv(os.path.join(DATA, "eurepoc_initial_access.csv"))
    n_coded = int(ia_all.n_coded.iloc[0])
    n_total = int(ia_all.n_total.iloc[0])
    n_pol = int(ia_all.n_political_coded.iloc[0])
    ia = ia_all.head(5).copy()
    ia["share"] = [f"{n / n_coded:.1%}" for n in ia.incidents]
    H.update(
        n_incidents_total=f"{n_total:,}",
        n_incidents_coded=n_coded,
        pct_incidents_coded=f"{n_coded / n_total:.1%}",
        n_phishing=_n(ia_all, "Phishing"),
        n_exploit=_n(ia_all, "Exploit Public-Facing Application"),
        pct_phishing=f"{_n(ia_all, 'Phishing') / n_coded:.1%}",
        pct_valid_accounts=f"{_n(ia_all, 'Valid Accounts') / n_coded:.1%}",
        n_political_coded=n_pol,
    )
    pol_tab = ia_all[ia_all.political_incidents > 0][["technique", "political_incidents"]]
    write(
        "initial_access.md",
        "How intrusions started",
        f"{n_coded} of {n_total:,} EuRepoC incidents ({n_coded / n_total:.1%}) carry a coded "
        "initial-access technique.\n\n"
        + md_table(ia[["technique", "incidents", "share"]], ["technique", "incidents", "share"])
        + f"\nAmong political targets specifically, only {n_pol} incidents are coded:\n\n"
        + md_table(pol_tab, ["technique", "incidents"]),
    )

    # ---- 8. the provenance gate -----------------------------------------
    with open(os.path.join(TABLES, "headline.json"), "w") as fh:
        json.dump({k: str(v) for k, v in H.items()}, fh, indent=1, sort_keys=True)
    print(f"  wrote tables/headline.json ({len(H)} figures)")
    print(
        f"\n  {n_unprot} of {n_measured} domains unprotected "
        f"({m.unprotected.mean():.1%}); {n_signed} of {len(dm)} zones signed"
    )


if __name__ == "__main__":
    main()
