"""Regression tests for defects an independent review found before v0.1.0.

Every test here failed before its fix. They are not coverage for its own sake:
each one pins a specific way this pipeline was recording a measurement it had
not made, which is the single failure mode the whole project is organized
against.

Nothing here touches the network. The functions under test are the pure ones;
the resolver-dependent paths are exercised by scripts/collect/verify_dns_posture.py
against a live sweep.
"""

import os
import sys

sys.path.insert(
    0,
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "collect"),
)
sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "analysis")
)

import pytest  # noqa: E402

import resolve_missing_sites  # noqa: E402
from check_readme import appears  # noqa: E402
from dns_posture import effective_policy, status_of  # noqa: E402
from resolve_missing_sites import extract, host_of  # noqa: E402


@pytest.fixture
def validate(monkeypatch):
    """validate() with the DNS existence check stubbed to 'the name exists'.

    The real check queries live DNS. A unit test that needs the network is a
    test that fails in CI for reasons that have nothing to do with the code, so
    the resolver is stubbed and the DNS behavior is left to
    verify_dns_posture.py, which runs against a real sweep by hand.
    """
    monkeypatch.setattr(resolve_missing_sites, "exists_in_dns", lambda d: True)
    return resolve_missing_sites.validate


class TestHostOf:
    """A Wikipedia infobox usually writes {{URL|senado.gov.co}} with no scheme.

    urlparse puts a scheme-less string in .path and leaves .netloc empty, so the
    first version returned None for exactly the common case and silently dropped
    18 institutions that DID publish a website.
    """

    def test_scheme_less_host_is_recovered(self):
        assert host_of("senado.gov.co") == "senado.gov.co"
        assert host_of("www.senate.gov.pk") == "senate.gov.pk"

    def test_scheme_less_host_with_path(self):
        assert host_of("nmijudiciary.gov/supremecourt") == "nmijudiciary.gov"

    def test_scheme_is_still_handled(self):
        assert host_of("https://www.example.gov.co/x") == "example.gov.co"

    def test_port_and_userinfo_are_stripped(self):
        assert host_of("https://user@example.gov.co:8443/x") == "example.gov.co"

    def test_empty_is_none(self):
        assert host_of("") is None


class TestExtract:
    def test_url_template_without_scheme(self):
        assert extract("| website = {{URL|senado.gov.co}}") == "senado.gov.co"

    def test_url_template_numbered_parameter(self):
        assert extract("| website = {{URL|1=house.gov.by}}") == "house.gov.by"

    def test_no_website_field_returns_none(self):
        assert extract("| leader = someone\n| seats = 100") is None

    def test_first_url_in_article_is_not_taken(self):
        # A citation is not a homepage. Taking the first link produced
        # "President of Senegal -> businessdailyafrica.com".
        wikitext = "Some prose.<ref>https://www.businessdailyafrica.com/x</ref>\n"
        assert extract(wikitext) is None


class TestValidate:
    """validate() may only ever rule a candidate OUT."""

    def test_never_returns_accept(self, validate):
        for domain in ("senado.gov.co", "usa.gov", "example.org"):
            decision, _ = validate(domain, "CO")
            assert decision != "accept"

    def test_news_domain_is_rejected(self, validate):
        decision, reason = validate("businessdailyafrica.com", "SN")
        assert decision == "reject"
        assert "news" in reason

    def test_missing_domain_is_none_found(self, validate):
        assert validate(None, "CO")[0] == "none_found"

    def test_bare_ip_is_rejected(self, validate):
        assert validate("209.88.21.36", "NA")[0] == "reject"

    def test_apex_gov_counts_as_a_jurisdiction_claim(self, validate):
        # .gov is US-only and is itself a jurisdiction claim. Requiring a
        # trailing dot filed asfono.gov and guamlegislature.gov under
        # "nothing ties it to the jurisdiction", which is false.
        _, reason = validate("asfono.gov", "US")
        assert "nothing ties it to the jurisdiction" not in reason


class TestStatusOf:
    """The distinction the whole project rests on."""

    def test_valid_record_is_ok(self):
        assert status_of({"valid": True})[0] == "ok"

    def test_absent_record(self):
        assert status_of({"valid": False, "error": "A DMARC record does not exist."})[0] == "absent"

    def test_nxdomain_beats_absent(self):
        # "The domain does not exist" also contains "does not exist".
        got = status_of({"valid": False, "error": "The domain does not exist."})[0]
        assert got == "nxdomain"

    def test_timeout_is_lookup_failed_not_absent(self):
        got = status_of({"valid": False, "error": "The resolution lifetime expired."})[0]
        assert got == "lookup_failed"

    def test_unrecognised_error_falls_to_lookup_failed(self):
        assert status_of({"valid": False, "error": "something nobody has seen"})[0] == "invalid"

    def test_non_dict_is_lookup_failed(self):
        assert status_of(None)[0] == "lookup_failed"


class TestEffectivePolicy:
    """RFC 7489 6.6.3: an inherited record is governed by sp, not p."""

    def test_own_record_uses_p(self):
        dmarc = {
            "valid": True,
            "location": "example.gov",
            "tags": {"p": {"value": "reject"}, "sp": {"value": "none"}},
        }
        assert effective_policy(dmarc, "example.gov") == "reject"

    def test_inherited_record_uses_sp(self):
        # governo.gov.ao inherits gov.ao's record, which is p=quarantine sp=none.
        dmarc = {
            "valid": True,
            "location": "gov.ao",
            "tags": {"p": {"value": "quarantine"}, "sp": {"value": "none"}},
        }
        assert effective_policy(dmarc, "governo.gov.ao") == "none"

    def test_inherited_without_sp_falls_back_to_p(self):
        dmarc = {"valid": True, "location": "gov.ao", "tags": {"p": {"value": "reject"}}}
        assert effective_policy(dmarc, "governo.gov.ao") == "reject"

    def test_invalid_record_has_no_policy(self):
        assert effective_policy({"valid": False}, "example.gov") is None


class TestAppears:
    """The provenance gate's matcher."""

    def test_figure_ending_a_sentence_is_found(self):
        # A full stop is not a decimal point. Rejecting it failed four correct
        # figures on a correct README.
        assert appears("176", "phishing led 179 to 176. Both dwarf credentials.")
        assert appears("23%", "about 23%. It appears here because")

    def test_figure_inside_a_longer_number_is_not_found(self):
        assert not appears("19", "119 of them do")
        assert not appears("11", "111 domains publish strict SPF")

    def test_decimal_continuation_is_not_a_match(self):
        assert not appears("17", "17.7% of domains")

    def test_percentage_matches_exactly(self):
        assert appears("54.2%", "gives 54.2% of measured domains")
        assert not appears("4.2%", "gives 54.2% of measured domains")
