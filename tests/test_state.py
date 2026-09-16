import asyncio

from sources import Article
from state import State


def article(url="https://example.com/article", cves=None):
    return Article(
        title="Test article",
        url=url,
        source="Test",
        cves=cves or [],
    )


def test_published_article_is_known():
    state = State(retention_days=7)

    state.mark_published(
        "https://example.com/article",
        "Test article",
    )

    assert state.is_known("https://example.com/article")


def test_unknown_article_is_not_known():
    state = State(retention_days=7)

    assert not state.is_known("https://example.com/article")


def test_cve_is_tracked_after_publication():
    state = State(
        retention_days=7,
        kev_retro_days=14,
    )

    state.mark_published(
        "https://example.com/article",
        "Test article",
        cves=["CVE-2026-1234"],
    )

    assert "CVE-2026-1234" in state.tracked_cves()


def test_kev_escalation_detected():
    state = State(
        retention_days=7,
        kev_retro_days=14,
    )

    state.mark_published(
        "https://example.com/article",
        "Test article",
        cves=["CVE-2026-1234"],
    )

    pending = state.pending_kev_escalations(
        ["CVE-2026-1234"]
    )

    assert len(pending) == 1
    assert pending[0]["cve"] == "CVE-2026-1234"


def test_kev_escalation_is_not_repeated():
    state = State(
        retention_days=7,
        kev_retro_days=14,
    )

    state.mark_published(
        "https://example.com/article",
        "Test article",
        cves=["CVE-2026-1234"],
    )

    state.record_kev_escalation("CVE-2026-1234")

    assert state.pending_kev_escalations(
        ["CVE-2026-1234"]
    ) == []


def test_feed_recovery_resets_failure_counter():
    state = State(retention_days=7)

    from sources import FeedResult

    state.record_feed_results([
        FeedResult(
            name="TestFeed",
            articles=[],
            error="HTTP 500",
        )
    ])

    state.record_feed_results([
        FeedResult(
            name="TestFeed",
            articles=[article()],
        )
    ])

    assert state.unhealthy_feeds(threshold=1) == []