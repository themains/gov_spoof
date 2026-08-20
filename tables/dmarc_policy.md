# DMARC policy

Share of 613 measured domains.

| DMARC policy | domains | share |
|---|---|---|
| `p=reject` — blocks forged mail | 138 | 22.5% |
| `p=quarantine` — sends it to spam | 135 | 22.0% |
| `p=none` — monitors, blocks nothing | 117 | 19.1% |
| no DMARC record at all | 208 | 33.9% |
| record published but malformed | 15 | 2.4% |

Unprotected (`none`, absent or malformed): 340 of 613 = 55.5%

Collapsed to the institution, counting one unprotected only when no domain of it is protected: 326 of 594 = 54.9%
