# Websites resolved outside Wikidata

172 live institutions carried no website in Wikidata. A further 40 are recorded as not applicable: offices held by a person, usually a crown shared between realms, and bodies of states that no longer exist.

Three passes. The first reads the Wikipedia infobox `website` field. The second, for articles without one, takes the external links, keeps only hosts on that country's own ccTLD, and ranks them by whether the hostname names the branch. The third is a web search for what remains. All three produce candidates and none produces a decision: every candidate is then fetched, and the page that comes back is what decides it.

| outcome | institutions |
|---|---|
| accepted into the frame | 126 |
| rejected on review | 29 |
| still unresolved | 17 |
| not applicable | 40 |

Every accept and every reject carries the page title that decided it in `data/institution_sites_review.csv`. Nothing is accepted automatically: a matching country code confirms the country and says nothing about the institution, which is how a first draft of this offered Guatemala's Ministry of Agriculture as its Council of Ministers.

**The additions are worse defended than the frame they joined.**

| source | domains | unprotected |
|---|---|---|
| Wikidata `P856` | 493 | 54.2% |
| resolved and hand-confirmed | 120 | 60.8% |

An institution whose website nobody recorded is an institution with less administrative capacity, and it defends its mail worse. Every figure on this page is therefore a lower bound: the institutions still missing from the frame are, on this evidence, the weakest ones.
