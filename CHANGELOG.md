# Changelog

## v0.1.1 — 2026-08-20

No data or figure changed; every number is identical to v0.1.0 and `make check`
ties all 73 of them to a generated table. But three claims in the v0.1.0 prose
were wrong, and an independent review of the rewrite caught them.

### Corrected

- **"Courts look best defended and executives worst."** Legislatures are worst,
  at 58.4% against the executives' 58.0% — and the table directly above the
  sentence bolds the legislature figure. The prose contradicted its own exhibit.
- **"The ordering survives" in the balanced 55-country subset.** Only the courts
  do. Legislatures go from worst in the unbalanced column to second best in the
  balanced one, and the spread across all four halves, from 11.8 points to 5.9.
- **"Executives are the only branch still pointing the same way after the
  control."** All three point the same way before and after; none changes sign.
  Executives keep the largest gap, which is a different and smaller claim.

### Changed

- The page was titled with the repository slug and opened with a section header
  announcing that we had looked, so the headline number arrived fifteen lines
  down. It opens with the number.
- "Reading the data honestly" is gone as a section. Its caveats were correct and
  quarantined, which asks a reader to leave a table to learn what the table can
  support. Each now sits with the claim it qualifies: malformed records and `sp`
  inheritance under the policy table, the exclusions with the denominator, the
  TCP/UDP failure beside the DNSSEC figure, the single-snapshot limit under the
  headline. Three caveats lost in the first draft of that move — the per-column
  failure ceiling, the rejection of a uniform DNSSEC column, and repeat
  measurement not having been done — are restored.
- Cut the bold-header list pattern from twelve instances to five, where it is a
  definition list rather than formatting standing in for prose, and thinned the
  punchline endings and negative-parallelism constructions.

## v0.1.0 — 2026-08-20

First tagged release. 613 institutional domains measured across 224
jurisdictions, with every figure on the README generated from the committed data
and gated against it.

### Corrected

- **DNSSEC was reported as "zero of 523". It is 132 of 613.** The collecting
  machine's nameserver answered UDP and dropped TCP. DMARC and SPF lookups
  travel over UDP and worked; `checkdmarc` asks for DNSKEY over TCP, and every
  one of those timed out into `false`. The run's failure-rate guard read the
  DMARC column, saw a healthy sweep, and passed. `dns_posture.py` now probes TCP
  against a known-signed zone before it starts, records which nameserver
  answered, writes `lookup_failed` rather than "unsigned" when none does, and
  applies the failure ceiling to every column separately.
- **"Courts are the best defended" did not hold the country fixed.** The four
  branches are measured in different sets of countries — supreme courts in 92,
  legislatures in 204 — so the raw ordering compared different worlds. Under
  country fixed effects every branch gap falls inside its own standard error.
  The section now reports the contrast both ways and states the identification
  base: 176 countries and 565 of 613 domains.
- **"Phishing is the single largest entry route" was a tie.** 179 incidents
  against 176 for public-facing exploits, from the 14.8% of EuRepoC incidents
  that carry a coded technique.
- **DMARC policy is now read as a receiver applies it.** Domains that inherit a
  parent record are scored on `sp`, not `p`. Four sit under a parent publishing
  a strict `p` with `sp=none`.

### Found by independent review, before tagging

An independent model reviewed the release diff. Nine defects survived
verification; all are fixed and each has a test that fails without its fix.

- `posture_tables.py` read `data/raw/eurepoc/`, which is gitignored, so the
  analysis crashed on any clean checkout — every CI run and every reader who
  cloned the repo. It now reads a committed aggregate.
- `host_of()` returned None for every scheme-less URL, which is how Wikipedia
  infoboxes usually write them (`{{URL|senado.gov.co}}`). 18 institutions whose
  website was in the article were recorded as having none.
- `dnssec_status` could never be `lookup_failed` once a nameserver was chosen,
  so a DNSKEY query that timed out was recorded as an unsigned zone — the
  original bug, one level down. A False is now qualified by checking the zone
  answers at all; 10 domains moved from "unsigned" to "we could not ask".
- The resolution table counted candidate evaluations as institutions, so its
  outcomes summed to 218 against a denominator of 172.
- `check-readme` did not cover the branch table's domain counts, and the README
  shipped 118 Supreme Court domains against a generated 116 while the gate
  reported success. Those counts are now exported.
- `exists_in_dns()` returned True when every query failed, so a run with no
  working resolver would have certified every candidate as resolvable.
- `verify_dns_posture.py` returned `dig`'s "connection timed out" text as an
  answer, scoring a DNSKEY on all 620 zones when the resolver was unreachable;
  and its comparisons could pass over an empty set. It now probes its resolver
  first and asserts both sides measured something.
- The batch-failure path recorded only DMARC as failed, leaving SPF to be read
  as "publishes no record".
- Prose arithmetic: the domain-control paragraph named 7 exclusions and claimed
  8, omitting the parallel body; the Method section still said 199 jurisdictions
  against 224 in the opening.

### Added

- `analysis/posture_tables.py` generates every figure the README quotes, and
  `analysis/check_readme.py` fails the build when the prose and the tables
  disagree. Neither existed; numbers were computed by hand and pasted, which is
  how a fabricated column reached the front page.
- `scripts/collect/verify_dns_posture.py` re-measures each sweep through `dig`
  on a second resolver and exits non-zero where the two disagree. Conflicts are
  re-asked at the domain's own nameservers, because both sides cache.
- `scripts/collect/site_content.py` checks whether the institution still
  controls the domain. Two do not: `apn-dz.org`, Algeria's Assemblée Populaire
  Nationale, went parliament to "This website is for sale!" to a detective
  agency in Ichikawa, and it publishes valid DMARC, so the old table scored the
  detective agency as a parliament that blocks forged mail.
- `scripts/collect/resolve_missing_sites.py` recovers institutional websites
  Wikidata does not have, in three passes — infobox field, article links ranked
  by branch, then web search — with every candidate confirmed by fetching the
  page. 126 accepted, 29 rejected, 17 still unresolved.
- CI runs the gates on push and pull request. Collection never runs in a build.

### Known limits

- One snapshot, one day. Nothing here separates a lasting configuration from a
  momentary one.
- 17 institutions remain unresolved: juntas, closed states, sub-national courts
  filed as national, and small states with no separate site.
- Resolved domains are 60.8% unprotected against 54.2% for Wikidata-sourced
  ones, so every figure is a lower bound.
