# Open House

**Most of the world's national institutions can be impersonated by email.** Of
613 domains measured across 224 jurisdictions — parliaments, presidencies,
cabinets and supreme courts — 340 publish no DMARC policy that blocks a forged
`From:` address. That is 55%.

A house is what a legislature calls itself. *Open* is what its security posture
usually turns out to be.

| DMARC policy | share of 613 measured domains |
|---|---|
| `p=reject` — blocks forged mail | **22.5%** |
| `p=quarantine` — sends it to spam | 22.0% |
| `p=none` — monitors, blocks nothing | 19.1% |
| no DMARC record at all | **33.9%** |
| record published but malformed | 2.4% |

Four things about that table decide how much weight it carries.

The last row is its own category, not a rounding error. An institution
publishing a broken record tried and failed, which is a different fact and a
different remedy from never having tried. Three publish two conflicting DMARC
records each — Belarus, El Salvador, Equatorial Guinea — which under RFC 7489
means receivers ignore both. It looks strict and protects nothing.

The policy is read the way a receiver applies it, not the way the record is
written. 33 domains carry no record of their own and inherit the organisational
domain's, where RFC 7489 hands control to the subdomain tag `sp`. Four sit under
a parent publishing a strict `p` with `sp=none`: read off `p` they look
defended, and nothing blocks a forgery of them.

The denominator is domains we could actually ask about. The sweep covers 647,
every national institution Wikidata records with a website, and 34 are excluded:
17 no longer resolve at all, 9 sit behind unreachable nameservers, and 8 turned
out not to be the institution's domain. Every result carries a status — `ok`,
`absent`, `invalid`, `nxdomain` or `lookup_failed` — and anything unrecognised
falls to `lookup_failed`, because conflating "publishes nothing" with "we could
not ask" is the easiest way to manufacture a finding here, and an early version
of this code did exactly that. The unreachable ones were re-checked through a
second resolver and none changed, so those exclusions are stable rather than
transient.

And the unit is the domain, while the claim is about institutions. An
institution can publish several — the Folketing has four, one Faroese and one
Greenlandic — so the share could in principle be carried by a few bodies with
neglected aliases. It isn't: counting an institution unprotected only when
*none* of its domains is protected gives 326 of 594, or 54.9%.

Every number here comes from a single sweep on one day. A nameserver that was
slow that afternoon is recorded as we found it, and nothing here separates a
lasting configuration from a momentary one.

## Neither SPF nor DNSSEC stops it

314 domains publish a hard-fail SPF policy, far more than publish enforcing
DMARC. But SPF authenticates the envelope sender, and receivers do not align
that against the `From:` address a person actually reads. **135 domains publish
strict SPF and have no effective DMARC policy.** The work was done and the
forgery still lands.

DNSSEC is enabled on 132 of the 613 zones we could test, about 22%. It is here
because the same lookup returns it, not because it bears on spoofing: DNSSEC
protects the path a resolver takes to an answer, not the header a reader sees.
Measuring it is easy to get wrong in one specific way. DNSKEY queries travel
over TCP where DMARC and SPF travel over UDP, so a network that intercepts
UDP/53 answers every DMARC query and silently drops every DNSKEY query — a sweep
that looks completely healthy and in which no zone anywhere appears signed. An
earlier version of this page reported exactly that. The sweep now probes TCP
against a known-signed zone before it starts, records which nameserver answered,
and writes `lookup_failed` rather than "unsigned" when none does.

## These are lower bounds

Wikidata records no website for 172 live institutions in the frame, so they were
never measured. We resolved what we could from Wikipedia and confirmed each one
by fetching the page: 126 accepted, 29 rejected, 17 still unresolved. A further
40 entries cannot have a website to find — a crown shared between realms is a
person, not an institution with a domain — and are recorded as such rather than
counted as failures.

| where the domain came from | domains | unprotected |
|---|---|---|
| Wikidata `P856` | 493 | 54.2% |
| resolved and hand-confirmed | 120 | **60.8%** |

The institutions nobody had recorded a website for are markedly worse defended
than the ones already in the frame. The administrative capacity that keeps a
public record current is the capacity that configures a DMARC policy, so the
measurement is biased in a knowable direction. **Every figure on this page
understates the problem**, and the 17 institutions still unresolved are, on this
evidence, the weakest of all.

That also means the frame cannot be expanded for free. Resolution succeeds where
a country is well documented, so `domain_source` travels into the posture table
and every result can be recomputed on the Wikidata-sourced domains alone. Doing
that moves the branch gaps below by about a percentage point and leaves them
inside their standard errors.

## Two institutions no longer own their domain

Spoofing is the cheap attack. Losing the domain outright is the expensive one,
and it has already happened.

`apn-dz.org` belonged to Algeria's Assemblée Populaire Nationale. The Internet
Archive has it serving the parliament in 2005, sitting on a *"This website is
for sale!"* parking page by 2015, and today it is a private detective agency in
Ichikawa, Japan. `asambleanacionalvenezuela.org` served Venezuela's National
Assembly in 2020 and now serves an Indonesian gambling site.

Whoever holds a lapsed institutional domain inherits everything still pointing
at it: old links, old correspondence, printed citations, and the ability to send
mail that is not a forgery at all, because they own the domain. The Algerian
domain publishes a valid DMARC record, so until this check existed the table
above counted it as a parliament that blocks forged mail.

Those 2 are excluded, with 2 Wikidata entries that were never institutional, 3
bodies that no longer exist, and 1 parallel body — Venezuela's supreme tribunal
in exile, where the sitting court is already in the frame. 8 domains in all,
each verdict evidenced in `data/domain_control_review.csv`. Wikidata's `P856` is
whatever someone typed and nothing validates it: it gave India's head of state
an SEO blog article as an official website, and Pakistan's Supreme Court the
homepage of a press-freedom NGO.

## The branches differ across countries, not within them

| branch | domains | countries | unprotected |
|---|---|---|---|
| Supreme courts | 116 | 92 | 46.6% |
| Heads of state | 140 | 137 | 55.7% |
| Legislatures | 214 | 204 | **58.4%** |
| Executives / governments | 143 | 136 | 58.0% |

Courts look best defended and executives worst. That ordering does not survive
the obvious control, because the four branches are not measured in the same
countries. Supreme courts appear in 92 of them and legislatures in 204, since
Wikidata records highest courts more thinly and does so for states that document
themselves well. The column compares different sets of countries, and a
difference between branches is indistinguishable from a difference between the
countries each branch is drawn from.

Holding the country fixed separates them. The contrast is identified off the 176
countries with at least two branches measured, covering 565 of the 613 domains;
a country with only one branch is absorbed by its own fixed effect and tells the
comparison nothing. Difference against supreme courts in percentage points,
standard errors clustered by country:

| contrast | no country FE | country FE |
|---|---|---|
| Heads of state | +9.2 (6.5) | +2.6 (9.2) |
| Legislatures | +11.9 (5.6) | +4.3 (8.2) |
| Executives | +11.5 (6.4) | +6.1 (8.9) |

Every gap shrinks and none is distinguishable from zero. The same shows without
a model, on the 55 countries where all four branches were measured: supreme
courts at 46.7%, legislatures 50.9%, heads of state 51.8%, executives 52.6%. The
ordering survives there, at half the spread the unbalanced column shows.

So the branch gap is a fact about which countries each branch is observed in.
This frame was built with four branches precisely to make the within-country
comparison possible, and on this outcome it does not find one. Executives are
the only branch still pointing the same way after the control, at +6.1 points
against a standard error of 8.9, which is a direction worth measuring again.

## The five countries that mandate DMARC

Five countries require DMARC on government domains: the US, UK, Netherlands, New
Zealand and Denmark. Their institutions reach **60.0%** at `p=reject`, against
**21.2%** elsewhere.

Read that the way you read the branch table, and for the same reason. These five
are also among the richest and most technically capable states in the frame, and
20 domains across 5 countries cannot separate the mandate from the capacity of
the countries that write mandates. A policy effect is a plausible reading here,
not a demonstrated one.

Compliance is uneven even among them, which is the firmer observation. The
United States and the Netherlands enforce across every branch. Denmark mandates
`p=reject` and its parliament sits at `quarantine`. New Zealand's
`parliament.nz` publishes no DMARC record at all.

## Why it matters

An institution whose domain can be spoofed is one where any citizen, journalist
or member of staff can receive mail that appears to come from it and passes
every check an ordinary mail client performs.

That matters here more than for most organisations, because of how attacks on
political targets begin. In the [European Repository of Cyber Incidents][eurepoc],
among incidents with a coded initial-access technique:

| how intrusions started | share |
|---|---|
| Phishing | 35.4% |
| Exploiting a public-facing application | 34.8% |
| Stolen credentials | 10.9% |

Phishing and public-facing exploits are the two dominant entry routes and they
are level, 179 incidents against 176. Both run more than three times the share
attributable to leaked passwords, which is what most research on this topic
measures. Spoofable domains are the cheap end of the first.

Read the coverage before the shares. EuRepoC codes an initial-access technique
for 506 of 3,414 incidents, or 14.8%, and better-documented intrusions get
richer coding, so this is not a random seventh of the data. Among political
targets specifically only 11 incidents are coded — too few to carry anything,
and among those few exploits lead phishing 5 to 3. The table describes intrusions
in general. It does not describe intrusions into legislatures, and this project
cannot yet tell you whether those differ.

The fix is one DNS record. It costs nothing and requires no procurement.

**Posture is not outcome.** This measures one surface. It does not show that any
institution has been compromised, and a well-configured domain is not a safe
one. Incident data is included here to test that link; the test has not been run.

## Method

- **Frame** — Wikidata: legislative body (`P194`), head-of-state office
  (`P1906`), executive (`P208`), highest court (`P209`), restricted to entities
  with an ISO-3166 country code. A census of national institutions, not a
  convenience sample of domains. It reaches 238 jurisdictions; the 224 above are
  those where at least one institutional domain could be measured.
- **Known frame edges** — `gov.uk` serves three jurisdictions in the frame, and
  Heard Island resolves to the Supreme Court of the Australian Capital
  Territory. Neither moves a headline figure; both are visible in
  `data/institution_domains.csv`.
- **Measurement** — [`checkdmarc`][cd] for DMARC, SPF, MTA-STS and DNSSEC, then
  `verify_dns_posture.py`, which re-asks the same questions through `dig` on a
  different resolver and exits non-zero where the two disagree. It runs against
  each sweep by hand rather than in a build, because it touches the network and
  no build target here is allowed to.
- **What we send** — every posture lookup is passive DNS. The one exception is
  `site_content.py`, which makes a single unauthenticated GET of the homepage
  each institution publishes, to check the domain still belongs to the body it
  is filed under. That is the same request a browser makes when a person visits
  the page, and it is the whole of it: **nothing here scans, enumerates paths,
  authenticates, or touches mail infrastructure.**
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
