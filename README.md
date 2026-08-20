# open_house

**Most of the world's national institutions can be impersonated by email.**

A house is what a legislature calls itself. *Open* is what its security posture
usually turns out to be.

We measured whether the email domains of national legislatures, heads of state,
executives and supreme courts can be spoofed. The sweep covers 647 domains —
every national institution Wikidata records with a website — of which 613,
across 224 jurisdictions, could be measured.

## What we found

**55% have no effective protection against email spoofing.**

| DMARC policy | share of 613 measured domains |
|---|---|
| `p=reject` — blocks forged mail | **22.5%** |
| `p=quarantine` — sends it to spam | 22.0% |
| `p=none` — monitors, blocks nothing | 19.1% |
| no DMARC record at all | **33.9%** |
| record published but malformed | 2.4% |

That is 340 of 613 domains. An institution can publish several — the Folketing
has four, one Faroese and one Greenlandic — so the share could in principle be
carried by a few bodies with many neglected aliases. It isn't: counting an
institution unprotected only when *none* of its domains is protected gives 326
of 594, or 54.9%. The finding is about institutions, not about spare domains.

SPF is far more common than DMARC — 314 domains publish a hard-fail policy. But
SPF authenticates the envelope sender, and receivers do not align that against
the `From:` address a human actually sees. **135 domains publish strict SPF and
have no effective DMARC policy.** The work was done and the forgery still lands.
It is the widely-adopted protocol that doesn't stop the attack.

DNSSEC is enabled on 132 of the 622 zones we could test, about 21%. It appears
here because the same lookup returns it, not because it bears on spoofing:
DNSSEC protects the path a resolver takes to an answer, not the header a reader
sees.

### These are lower bounds

Wikidata records no website for 172 live institutions in the frame, so they were
never measured. We resolved what we could from Wikipedia and confirmed each one
by hand: 126 accepted, 46 rejected, 46 still unresolved. A
further 40 entries cannot have a website to find — a crown shared between
realms is a person, not an institution with a domain — and are recorded as such
rather than counted as failures. What came back settles how to read every other
number here.

| where the domain came from | domains | unprotected |
|---|---|---|
| Wikidata `P856` | 493 | 54.2% |
| resolved and hand-confirmed | 120 | **60.8%** |

The institutions nobody had bothered to record a website for are markedly worse
defended than the ones that were already in the frame. That is not a surprise
once stated — the administrative capacity that keeps a public record current is
the same capacity that configures a DMARC policy — but it means the measurement
is biased in a knowable direction. **Every figure on this page understates the
problem**, and the 46 institutions still unresolved are, on this evidence, the
weakest of all.

It also means the frame cannot be expanded for free. Resolution succeeds where a
country is well documented, so `domain_source` is carried through to the posture
table and every result can be recomputed on the original Wikidata domains alone.
Doing that changes nothing important: the branch gaps below move by around a
percentage point and stay inside their standard errors.

### Two institutions no longer own their domain

Spoofing is the cheap attack. Losing the domain outright is the expensive one,
and it has already happened.

`apn-dz.org` belonged to Algeria's Assemblée Populaire Nationale. The Internet
Archive has it serving the parliament in 2005, sitting on a *"This website is
for sale!"* parking page by 2015, and today it is a private detective agency in
Ichikawa, Japan. `asambleanacionalvenezuela.org` served Venezuela's National
Assembly in 2020 and now serves an Indonesian gambling site.

Whoever holds a lapsed institutional domain inherits everything that still
points at it: old links, old correspondence, printed citations, and the ability
to send mail that is not a forgery at all, because they own the domain. The
Algerian domain publishes a valid DMARC record, so before this check ran, the
table on this page counted it as a parliament that blocks forged mail. It was
scoring the detective agency.

Those 2 are excluded from the figures above, along with 2 Wikidata entries that
were never institutional and 3 bodies that no longer exist — 8 domains dropped
in all. The evidence for each verdict is in `data/domain_control_review.csv`.

The second category is worth its own warning. Wikidata's `P856` is whatever
someone typed, and nothing validates it. It gave India's head of state an SEO
blog article as an official website, and Pakistan's Supreme Court the homepage
of a press-freedom NGO.

### The branches differ across countries, not within them

| branch | domains | countries | unprotected |
|---|---|---|---|
| Supreme courts | 118 | 92 | 46.6% |
| Heads of state | 140 | 137 | 55.7% |
| Legislatures | 214 | 204 | **58.4%** |
| Executives / governments | 143 | 136 | 58.0% |

Courts look best defended and executives worst. That ordering does not survive
the obvious control.

The four branches are not measured in the same countries. Supreme courts appear
in 92 of them and legislatures in 204, because Wikidata records highest courts
more thinly and does so for states that document themselves well. So the column
above compares different sets of countries, and a difference between branches is
indistinguishable from a difference between the countries each branch is drawn
from.

Holding the country fixed separates the two. The contrast below is identified
off the 176 countries with at least two branches measured, covering 565 of the
613 domains — a country with only one branch is absorbed by its own fixed effect
and tells the comparison nothing. Difference against supreme courts in
percentage points, standard errors clustered by country:

| contrast | no country FE | country FE |
|---|---|---|
| Heads of state | +9.2 (6.5) | +2.6 (9.2) |
| Legislatures | +11.9 (5.6) | +4.3 (8.2) |
| Executives | +11.5 (6.4) | +6.1 (8.9) |

Every gap shrinks and none is distinguishable from zero. The same thing shows
without a model, on the 55 countries where all four branches were measured:
supreme courts sit at 46.7% and legislatures at 50.9%, heads of state at 51.8%
and executives at 52.6% — the ordering survives here, but the gap is half what
the unbalanced column shows.

The branch gap is a fact about which countries each branch is observed in, not
about branches. This frame was built with four branches precisely to make the
within-country comparison possible, and on this outcome it does not find one.
Executives are the only branch still pointing the same way after the control, at
+6.1 points against a standard error of 8.9 — a direction worth measuring
again, not a result.

### The five countries that mandate DMARC

Five countries require DMARC on government domains (US, UK, Netherlands, New
Zealand, Denmark). Their institutions reach **60.0%** at `p=reject`, against
**21.2%** elsewhere.

Read that the same way as the branch table above, and for the same reason. These
five are also among the richest and most technically capable states in the
frame, and 20 domains across 5 countries cannot separate the mandate from the
capacity of the countries that write mandates. A policy effect is a plausible
reading here, not a demonstrated one.

Compliance is uneven even among them, which is the more solid observation. The
United States and the Netherlands enforce across every branch. Denmark mandates
`p=reject` and its parliament sits at `quarantine`. New Zealand's
`parliament.nz` publishes no DMARC record at all. Whatever a mandate does, it
does not do it by itself.

## Why it matters

An institution whose domain can be spoofed is one where any citizen, journalist
or member of staff can receive mail that appears to come from it and passes
every check an ordinary mail client performs.

That matters here more than for most organisations, because of how attacks on
political targets actually begin. In the [European Repository of Cyber
Incidents][eurepoc], among incidents with a coded initial-access technique:

| how intrusions started | share |
|---|---|
| Phishing | 35.4% |
| Exploiting a public-facing application | 34.8% |
| Stolen credentials | 10.9% |

Phishing and public-facing exploits are the two dominant entry routes, and they
are level: 179 incidents against 176. Both are more than three times the share
attributable to leaked passwords, which is what most research on this topic
measures. Spoofable domains are the cheap end of the first.

Read the coverage before the shares. EuRepoC codes an initial-access technique
for 506 of 3,414 incidents, or 14.8%, and better-documented intrusions get
richer coding, so this is not a random seventh of the data. Among political
targets specifically only 11 incidents are coded — too few to carry anything,
and among those few, exploits lead phishing 5 to 3. The table describes
intrusions in general. It does not describe intrusions into legislatures, and
this project cannot yet tell you whether those differ.

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

**A DNSSEC answer needs a nameserver that speaks TCP.** DNSKEY queries go over
TCP where DMARC and SPF lookups go over UDP, and a resolver can serve one and
not the other. A network that intercepts UDP/53 will answer every DMARC query
and silently drop every DNSKEY query, which yields a sweep that looks completely
healthy and in which no zone anywhere appears signed. So the sweep probes TCP
against a known-signed zone before it starts, records which nameserver answered,
and writes `lookup_failed` rather than "unsigned" when none does. Every column
is checked against that ceiling separately, because a healthy DMARC column says
nothing about whether any other lookup got an answer. And a DNSSEC column that
comes back uniform in either direction is rejected by the verification pass: all
unsigned was the failure this guards against, and all signed would be a
validating resolver telling us the same kind of lie.

**34 domains are excluded**: 17 no longer resolve at all (Wikidata lists a site
that has gone away), 9 sit behind unreachable nameservers, and 8 turned out not
to be the institution's domain at all. The unreachable ones were re-checked
independently through a second resolver and none changed, so those exclusions
are stable rather than transient.

**A malformed record is its own category.** An institution publishing a broken
DMARC record tried and failed — a different fact, and a different remedy, from
never having tried. Three publish two conflicting DMARC records each (Belarus,
El Salvador, Equatorial Guinea), which under RFC 7489 means receivers ignore
both: it looks strict and protects nothing.

**Policy is read the way a receiver applies it.** 33 domains carry no record of
their own and inherit the organisational domain's, where RFC 7489 says the
subdomain policy tag `sp` governs. Four of them sit under a parent publishing a
strict `p` with `sp=none`. Read off `p` they look defended; read the way mail is
actually filtered, nothing blocks a forgery of them.

**One snapshot, one day.** Every number here comes from a single sweep. A
nameserver that was slow that afternoon is recorded as we found it, and nothing
separates a lasting configuration from a momentary one. Repeat measurement is
the obvious next step and has not been taken.

## Method

- **Frame** — Wikidata: legislative body (`P194`), head-of-state office
  (`P1906`), executive (`P208`), highest court (`P209`), restricted to entities
  with an ISO-3166 country code. A census of national institutions, not a
  convenience sample of domains. It reaches 238 jurisdictions; the 199 above are
  those where at least one institutional domain could actually be measured.
- **Known frame edges** — `gov.uk` serves three jurisdictions in the frame, and
  Heard Island resolves to the Supreme Court of the Australian Capital
  Territory. Neither moves a headline figure; both are visible in
  `data/institution_domains.csv`.
- **Measurement** — [`checkdmarc`][cd] for DMARC, SPF, MTA-STS and DNSSEC, then
  `verify_dns_posture.py`, which re-asks the same questions through `dig` on a
  different resolver and exits non-zero where the two answers disagree. It runs
  against each sweep by hand rather than in a build, because it touches the
  network and no build target here is allowed to.
- **What we send** — every posture lookup is passive DNS. The one exception is
  `site_content.py`, which makes a single unauthenticated GET of the homepage
  each institution publishes, to check the domain still belongs to the body it
  is filed under. That is the same one request a browser makes when a person
  visits the page, and it is the whole of it: **nothing here scans, enumerates
  paths, authenticates, or touches mail infrastructure.** An earlier version of
  this page said no request was made at all, which stopped being true the moment
  the domain-control check existed.
- **Reproduce** — `make setup`, then the collectors in `scripts/collect/`.
  `make check` regenerates every figure on this page from the frozen snapshot
  and fails if the page cites one the tables do not produce.

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
