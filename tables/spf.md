# SPF

| SPF all-qualifier | domains |
|---|---|
| fail | 314 |
| softfail | 169 |
| (no SPF record) | 125 |
| neutral | 5 |

314 domains publish a hard-fail (`-all`) policy.

Of those, 135 have no effective DMARC policy: strict SPF, and nothing stopping a forged `From:` address.
