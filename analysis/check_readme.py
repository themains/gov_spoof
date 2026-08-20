"""Fail when the README and the generated tables disagree.

The DNSSEC error survived because no mechanism connected a sentence to a number.
"DNSSEC: zero of 523" was true of a variable in someone's session and false of
the world, and nothing in the repo was in a position to notice. This is the
missing link: every figure posture_tables.py exports has to appear in the
README, verbatim, or the build fails.

It catches the common failure directly -- regenerate a table, forget the
paragraph that cites it -- and it makes stale prose a build error rather than a
thing a reader finds. It is deliberately dumb: substring presence, no parsing.
A cleverer version that tried to locate each number in context would need a
model of the prose, and would fail open the first time someone rephrased a
sentence.

WHAT IT DOES NOT CATCH. A figure that appears in the README for an unrelated
reason satisfies its own check by coincidence, and a wrong sentence wrapped
around a right number passes. This gate keeps the arithmetic honest; it cannot
keep the interpretation honest. Nothing automatic can.

Usage:  python analysis/check_readme.py
"""

import json
import os
import re
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
HEADLINE = os.path.join(REPO, "tables", "headline.json")
README = os.path.join(REPO, "README.md")

# Figures the README has no reason to quote. Empty on purpose: the README
# currently cites every figure posture_tables.py exports, and keeping it that
# way means a number can only enter the tables by also entering the prose.
# Anything added here is a decision somebody made rather than a silent omission.
NOT_IN_PROSE = set()


def appears(value, text):
    """Is `value` in `text` as a whole figure rather than inside a longer one?

    Plain substring matching is not enough. "19" occurs inside "119", "11"
    inside "111", "36" inside "436": with a bare `in` test, most of the small
    counts here would satisfy their own check against some unrelated number
    elsewhere on the page, and the gate would report success while proving
    nothing. Guarding both sides against adjacent digits fixes it.

    The trailing guard has to tell a decimal point from a full stop, which look
    identical and mean opposite things. Rejecting any following period sounds
    safe and is not: it fails every figure that ends a sentence, which is most of
    them. The first version of this function did that and reported four false
    failures on a correct README. A period only continues a number when a digit
    follows it.
    """
    return re.search(r"(?<![\d.])" + re.escape(value) + r"(?!\d)(?!\.\d)", text) is not None


def main():
    if not os.path.exists(HEADLINE):
        sys.exit("no tables/headline.json; run 'make tables' first")
    with open(HEADLINE) as fh:
        figures = json.load(fh)
    with open(README) as fh:
        readme = fh.read()

    missing = {k: v for k, v in figures.items() if k not in NOT_IN_PROSE and not appears(v, readme)}
    checked = len(figures) - len(NOT_IN_PROSE)

    if missing:
        print(f"  FAIL: {len(missing)} generated figure(s) do not appear in README.md:")
        for k, v in sorted(missing.items()):
            print(f"    {k:34s} = {v}")
        print("\n  Either the README is stale, or the table changed under it.")
        print("  Re-read the paragraph that cites each one before editing.")
        sys.exit(1)

    print(f"  ok: all {checked} generated figures appear in README.md")


if __name__ == "__main__":
    main()
