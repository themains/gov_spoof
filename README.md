# open_house

**Most of the world's national institutions can be impersonated by email.**

A house is what a legislature calls itself. *Open* is what its security posture
usually turns out to be.

We measured whether the email domains of national legislatures, heads of state,
executives and supreme courts can be spoofed — 523 domains across 238
jurisdictions, every national institution Wikidata records with a website.

## What we found

**54% have no effective protection against email spoofing.**

| DMARC policy | share of 502 measured domains |
|---|---|
| `p=reject` — blocks forged mail | **24.3%** |
| `p=quarantine` — sends it to spam | 21.5% |
| `p=none` — monitors, blocks nothing | 17.7% |
| no DMARC record at all | **34.3%** |
| record published but malformed | 2.2% |

**DNSSEC: zero of 523.** Not one national institution has it enabled.

SPF is far more common than DMARC — 264 domains publish a hard-fail policy. But
SPF does not protect the `From:` address a human actually sees. It is the
widely-adopted protocol that doesn't stop the attack.

### Courts are the best defended, executives the worst

| branch | unprotected |
|---|---|
| Supreme courts | 44.7% |
| Heads of state | 53.3% |
| Legislatures | 57.1% |
| **Executives / governments** | **60.0%** |

Because the four branches are measured *within the same countries*, this
comparison holds national wealth, technical capacity and threat environment
fixed. The gap is about institutions, not about which countries are rich.

### Mandates work, where they are enforced

Five countries require DMARC on government domains (US, UK, Netherlands, New
Zealand, Denmark). Their institutions reach **57.9%** at `p=reject`, against
**23.0%** elsewhere.

But compliance is uneven even among them. The United States and the Netherlands
enforce across every branch. Denmark mandates `p=reject` and its parliament sits
at `quarantine`. New Zealand's `parliament.nz` publishes no DMARC record at all.
*(19 domains across 5 countries — indicative, not decisive.)*

## Why it matters

An institution whose domain can be spoofed is one where any citizen, journalist
or member of staff can receive mail that appears to come from it and passes
every check an ordinary mail client performs.

That matters here more than for most organisations, because of how attacks on
political targets actually begin. In the [European Repository of Cyber
Incidents][eurepoc], among incidents with a coded initial-access technique:

| how intrusions started | share |
|---|---|
| **Phishing** | **35.4%** |
| Exploiting a public-facing application | 34.8% |
| Stolen credentials | 10.9% |

Phishing is the single largest entry route — more than three times the share
attributable to leaked passwords, which is what most research on this topic
measures. Spoofable domains are the cheap end of that attack.

The fix is one DNS record. It costs nothing and requires no procurement.

## What this does not show

**Posture is not outcome.** This measures one surface. It does not show that any
institution has been compromised, and a well-configured domain is not a safe
one. Incident data is included here to test that link; the test has not been run.

## Reading the data honestly

**A failed lookup is not an absent record.** Every result is `ok`, `absent`,
`invalid`, `nxdomain` or `lookup_failed`, and anything unrecognised falls to
`lookup_failed`. Conflating "publishes nothing" with "we could not ask" is the
easiest way to manufacture a finding in this area, and an early version of this
code did exactly that.

**21 domains are excluded**: 15 no longer resolve at all (Wikidata lists a site
that has gone away) and 6 sit behind unreachable nameservers. All 21 were
re-checked independently and **none changed**, so the exclusions are stable
rather than transient.

**A malformed record is its own category.** An institution publishing a broken
DMARC record tried and failed — a different fact, and a different remedy, from
never having tried. One country publishes two conflicting DMARC records, which
under RFC 7489 means receivers ignore both: it looks strict and protects nothing.

## Method

- **Frame** — Wikidata: legislative body (`P194`), head-of-state office
  (`P1906`), executive (`P208`), highest court (`P209`), restricted to entities
  with an ISO-3166 country code. A census of national institutions, not a
  convenience sample of domains.
- **Measurement** — [`checkdmarc`][cd] for DMARC, SPF, MTA-STS and DNSSEC. All
  lookups are passive DNS. **Nothing in this project contacts an institution's
  infrastructure**; there is no active code path.
- **Reproduce** — `make setup`, then run the collectors in
  `scripts/collect/`. Raw responses are snapshotted before parsing, so results
  can be re-derived without re-querying.

## Disclosure

DMARC and DNSSEC status is public configuration: anyone can resolve any of it in
a single DNS query, and it is already published commercially by sector. It is not
exploitable in itself — the risk falls on people *receiving* spoofed mail. So it
is published per institution, because naming is what creates accountability.

Work on exploitable exposure — services and vulnerabilities — will be reported
**in aggregate only**, and findings will go to the affected institution's
national CSIRT before publication. That distinction is enforced by a build gate,
not by good intentions.

## Related

- [themains/pwned_pols][pp] — breach exposure of politicians' email addresses,
  the project this grew out of
- Supersedes [themains/secure_gov][sg]

[eurepoc]: https://eurepoc.eu/
[cd]: https://github.com/domainaware/checkdmarc
[pp]: https://github.com/themains/pwned_pols
[sg]: https://github.com/themains/secure_gov
