# open_house

**How exposed are national legislatures?**

A house is what a legislature calls itself. *Open* is what its security posture
often turns out to be — open ports, open relays, open resolvers. An open house
is one anyone can walk into.

## The question, and why this framing

Earlier work on politician email breaches ([themains/pwned_pols][pp]) measured
how often a legislator's address appears in a public breach corpus. Checking
that measure against expert-coded incident data changed the question.

Of 506 incidents in the [European Repository of Cyber Incidents][eurepoc]
carrying a coded MITRE initial-access technique, intrusions begin with:

| how the intrusion started | share |
|---|---|
| Phishing | 35.4% |
| Exploiting a public-facing application | 34.8% |
| **Stolen credentials** | **10.9%** |

Credential exposure is roughly one entry route in nine. A perfect measure of it
would sit upstream of about a tenth of what actually happens. This project
measures all three surfaces instead, and at the level of the institution rather
than the individual address.

| surface | vector share | instrument |
|---|---|---|
| Phishing | 35.4% | DMARC policy, SPF qualifier, MTA-STS, DNSSEC |
| Public-facing exploit | 34.8% | Censys certificate pivot → Shodan CPE → NVD → EPSS |
| Credentials | 10.9% | domain-level exposure imported from `pwned_pols` |

Outcomes come from EuRepoC, institutional capacity from the IPU's *World
e-Parliament Report*, and country controls from the World Bank, UN EGDI, ITU GCI
and V-Dem.

## Ethics

**Passive only.** Every measurement queries an index that already exists.
Nothing here contacts a parliament's infrastructure. That is a property of the
architecture rather than a setting — there is no active code path to disable.
It is also why this uses Censys and Shodan directly rather than an orchestrator
such as SpiderFoot, which ships subdomain brute-forcing and port scanning among
its modules.

**Two disclosure tiers**, because the categories are not alike:

- *Exploitable exposure* — services and CVEs — is reported **in aggregate only**,
  by region or income group. Naming which legislature runs an exploitable
  service publishes an attack path.
- *Public policy configuration* — DMARC, DNSSEC — resolves in a single DNS
  lookup by anyone, is already published by sector commercially, and is not
  exploitable in itself; the risk falls on recipients of spoofed mail rather
  than on the institution. Naming is defensible here, and naming is what creates
  accountability.

**Findings reach the affected institution before they are published**, through
its national CSIRT. That route is built before collection, not improvised after
a finding.

## Measurement notes that matter

**A DNS timeout is not an absent record.** Every lookup is classified `ok`,
`absent`, `invalid` or `lookup_failed`, and anything unrecognised resolves
toward *we do not know*. Conflating the two manufactures findings, and this is
not hypothetical: the first three-domain test recorded a timeout against a
parliament that would otherwise have been scored as publishing no DMARC at all.
The same confusion cost the predecessor project roughly 270 addresses.

**A malformed record is its own category.** A legislature publishing a broken
DMARC record tried and failed — a different fact, and a different remedy, from
never having tried.

**Resolvers are pinned.** Public resolvers, fixed in the collector, so a
measurement does not depend on whatever the local network happens to hand out.

## Status

Early. The email-authentication sweep runs; the scanning tier awaits research
access to Censys and Shodan.

Supersedes [themains/secure_gov][sg], which proposed this with SpiderFoot and
was never built.

[pp]: https://github.com/themains/pwned_pols
[eurepoc]: https://eurepoc.eu/
[sg]: https://github.com/themains/secure_gov
