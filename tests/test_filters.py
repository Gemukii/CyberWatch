"""Tests for the filtering pipeline: exclusion, scoring, deduplication."""

import pytest

import filters
from sources import Article
from state import State, canonical_url, normalize_title


def article(**kwargs) -> Article:
    base = {"title": "Title", "url": "https://example.test/a", "source": "Test"}
    base.update(kwargs)
    return Article(**base)


# --------------------------------------------------------------------------- #
# Normalization
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "left,right",
    [
        ("https://ex.test/a/?utm_source=x&id=3", "https://EX.test/a?id=3#comments"),
        ("https://ex.test/b/", "https://ex.test/b"),
        ("https://ex.test/c?fbclid=abc", "https://ex.test/c"),
    ],
)
def test_equivalent_urls(left, right):
    assert canonical_url(left) == canonical_url(right)


def test_distinct_urls_stay_distinct():
    assert canonical_url("https://ex.test/a?id=1") != canonical_url("https://ex.test/a?id=2")


def test_title_normalization_ignores_punctuation_and_emoji():
    assert normalize_title("🔴 Critical  Flaw, Fortinet !") == "critical flaw fortinet"


# --------------------------------------------------------------------------- #
# Exclusions
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "title",
    [
        "Get this VPN deal for Black Friday",
        "Sponsored: why you need our EDR",
        "Free webinar on zero trust",
        "Top 10 tools for pentesting",
    ],
)
def test_promo_content_excluded(title):
    assert filters.is_excluded(article(title=title)) is not None


@pytest.mark.parametrize(
    "title",
    [
        "Fortinet warns of actively exploited RCE flaw",
        "New ransomware group targets hospitals",
        "CERT-FR: vulnérabilité critique dans Ivanti",
    ],
)
def test_legitimate_article_kept(title):
    assert filters.is_excluded(article(title=title)) is None


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #
def test_critical_article_scores_higher_than_generic():
    critical = article(
        title="Critical Fortinet zero-day actively exploited in the wild",
        source_weight=3,
        summary="CVE-2026-1234 allows remote code execution. CVSS: 9.8.",
        cves=["CVE-2026-1234"],
    )
    generic = article(
        title="Why security awareness matters in business",
        summary="Companies should train employees regularly about safety culture.",
    )
    assert filters.score_article(critical)[0] > filters.score_article(generic)[0] + 15


def test_kev_strongly_increases_score():
    without = article(title="Vulnerability in Acme Router", summary="A flaw was found." * 20,
                       cves=["CVE-2026-1111"])
    with_kev = article(title="Vulnerability in Acme Router", summary="A flaw was found." * 20,
                        cves=["CVE-2026-1111"], kev_cves=["CVE-2026-1111"])
    assert filters.score_article(with_kev)[0] >= filters.score_article(without)[0] + 8


def test_high_epss_increases_score():
    low = article(title="Flaw in Acme", summary="details " * 40, cves=["CVE-2026-2222"],
                  epss_max=0.001)
    high = article(title="Flaw in Acme", summary="details " * 40, cves=["CVE-2026-2222"],
                   epss_max=0.85)
    assert filters.score_article(high)[0] > filters.score_article(low)[0]


def test_keyword_in_title_counts_double():
    in_title = article(title="Ransomware attack on hospital", summary="x " * 60)
    in_body = article(title="Weekly roundup", summary="A ransomware attack occurred. " + "x " * 60)
    assert filters.score_article(in_title)[0] > filters.score_article(in_body)[0]


def test_bogus_cvss_ignored():
    """A "CVSS 99" must not inflate the score: the value is bounds-checked."""
    a = article(title="Flaw", summary="Rated CVSS: 99 by the vendor. " + "x " * 60)
    score, reasons = filters.score_article(a)
    assert not any("CVSS" in r for r in reasons)


# --------------------------------------------------------------------------- #
# Deduplication
# --------------------------------------------------------------------------- #
def test_same_story_two_sources_published_once():
    state = State(retention_days=7)
    a = article(
        title="Critical Fortinet zero-day actively exploited",
        url="https://cert.test/1", source="CERT-FR", source_weight=3,
        summary="CVE-2026-1234 remote code execution. CVSS: 9.8.", cves=["CVE-2026-1234"],
    )
    b = article(
        title="Critical Fortinet zero-day actively exploited!",
        url="https://thn.test/9", source="THN", source_weight=1,
        summary=a.summary, cves=["CVE-2026-1234"],
    )
    kept = filters.select_articles([a, b], state, min_score=5, similarity=0.72, limit=10)
    assert len(kept) == 1


def test_already_published_article_ignored():
    state = State(retention_days=7)
    a = article(
        title="Critical Fortinet zero-day actively exploited",
        url="https://cert.test/1?utm_source=rss", source_weight=3,
        summary="CVE-2026-1234 remote code execution. CVSS: 9.8.", cves=["CVE-2026-1234"],
    )
    state.mark_published(a.url, a.title)
    assert state.is_known("https://cert.test/1")          # same URL without tracking
    assert filters.select_articles([a], state, 5, 0.72, 10) == []


def test_sorted_by_descending_score():
    state = State(retention_days=7)
    high = article(title="Zero-day actively exploited in Fortinet", url="https://t.test/1",
                    source_weight=3, summary="CVE-2026-1234 RCE. CVSS: 9.8.",
                    cves=["CVE-2026-1234"], kev_cves=["CVE-2026-1234"])
    medium = article(title="Phishing campaign targets banks", url="https://t.test/2",
                      summary="A phishing campaign was observed. " + "x " * 60)
    kept = filters.select_articles([medium, high], state, 5, 0.72, 10)
    assert kept[0].url == high.url


def test_purged_past_retention():
    import time
    state = State(retention_days=1)
    state.mark_published("https://old.test/1", "Old title")
    # Simulate a publication from three days ago
    for key in list(state._seen):
        state._seen[key] = time.time() - 3 * 86400
    state._titles = type(state._titles)([(t, time.time() - 3 * 86400) for t, _ in state._titles])
    assert state.recent_titles() == []
    assert not state.is_known("https://old.test/1")