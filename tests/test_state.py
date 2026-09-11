"""
Tests for state without a database, and cycle robustness.

Notably covers three bugs fixed in v2:
  - marking limited to articles actually published
  - priming bounded by date, not a fixed message count
  - priming idempotence across Discord reconnects
"""

import asyncio
import time
import types

import pytest

import filters
from enrichment import extract_cves
from sources import Article, FeedResult
from state import State


def article(**kwargs) -> Article:
    base = {"title": "Title", "url": "https://example.test/a", "source": "Test"}
    base.update(kwargs)
    return Article(**base)


# --------------------------------------------------------------------------- #
# Fake Discord objects
# --------------------------------------------------------------------------- #
class FakeEmbed:
    def __init__(self, url, author_name=None, title="🔴 Reworded title"):
        self.url = url
        self.title = title
        self.author = types.SimpleNamespace(name=author_name) if author_name else None


class FakeMessage:
    def __init__(self, embeds, age_seconds=3600):
        self.embeds = embeds
        self.created_at = types.SimpleNamespace(timestamp=lambda: time.time() - age_seconds)


class FakeChannel:
    """Minimal Discord channel: readable history, sends are counted."""

    def __init__(self, messages=None, fail_on=()):
        self.messages = messages or []
        self.fail_on = fail_on          # indices of sends that must fail
        self.sent = 0

    def history(self, limit=None, after=None, oldest_first=None):
        async def generator():
            for message in self.messages:
                yield message
        return generator()

    async def send(self, *args, **kwargs):
        index = self.sent
        self.sent += 1
        if index in self.fail_on:
            raise RuntimeError("simulated send failure")
        return object()


# --------------------------------------------------------------------------- #
# Priming from Discord history
# --------------------------------------------------------------------------- #
def test_index_rebuilt_after_restart():
    """A restarting bot must not republish what's already in the channel."""
    original_title = "Critical Fortinet zero-day actively exploited"
    channel = FakeChannel([
        FakeMessage([FakeEmbed("https://cert.test/1", f"CERT-FR · {original_title}")]),
        FakeMessage([FakeEmbed(None, title="🛡️ Cyber watch")]),  # header, ignored
    ])
    state = State(retention_days=7)
    assert asyncio.run(state.prime_from_channel(channel)) == 1
    assert state.is_known("https://cert.test/1?utm_source=twitter")


def test_title_dedup_preserved_after_restart():
    """
    The published title is reworded by the LLM; author.name carries the
    original title and is what lets the bot recognize the same story
    elsewhere.
    """
    original_title = "Critical Fortinet zero-day actively exploited"
    channel = FakeChannel([
        FakeMessage([FakeEmbed("https://cert.test/1", f"CERT-FR · {original_title}")])
    ])
    state = State(retention_days=7)
    asyncio.run(state.prime_from_channel(channel))

    reprint = article(
        title=original_title + "!", url="https://other.test/9",
        summary="CVE-2026-1234 RCE. CVSS: 9.8.", cves=["CVE-2026-1234"],
    )
    assert filters.select_articles([reprint], state, 5, 0.72, 10) == []


def test_priming_idempotent_on_reconnect():
    """
    on_ready fires again on every Discord reconnect. Re-reading the whole
    history each time would be wasteful and costly.
    """
    channel = FakeChannel([FakeMessage([FakeEmbed("https://cert.test/1", "S · T")])])
    state = State(retention_days=7)
    assert asyncio.run(state.prime_from_channel(channel)) == 1
    assert asyncio.run(state.prime_from_channel(channel)) == 0   # already primed
    assert state.primed


def test_priming_failure_does_not_block_startup():
    """Without history-read permission, the bot still starts up."""
    class BrokenChannel:
        def history(self, **kwargs):
            async def generator():
                raise PermissionError("Missing Read Message History")
                yield  # pragma: no cover
            return generator()

    state = State(retention_days=7)
    assert asyncio.run(state.prime_from_channel(BrokenChannel())) == 0
    assert not state.primed          # reported as not primed in /cyber-status


# --------------------------------------------------------------------------- #
# Partial publication
# --------------------------------------------------------------------------- #
def test_only_published_articles_are_recorded():
    """
    Bug fixed in v2: an embed whose send fails must NOT be marked as seen,
    or it's lost for good.
    """
    pytest.importorskip("discord")
    import publisher
    from summarizer import Summary

    # send 0 = header, 1 = first article (fails), 2 = second article
    channel = FakeChannel(fail_on=(1,))
    items = [
        (article(url="https://a.test/1"), Summary(title="A", bullets=["x"], severity="Medium")),
        (article(url="https://a.test/2"), Summary(title="B", bullets=["y"], severity="Medium")),
    ]

    # publisher expects discord.HTTPException; widen the net for the test
    original = publisher.discord.HTTPException
    publisher.discord.HTTPException = RuntimeError
    try:
        posted = asyncio.run(publisher.publish(channel, items, "gemini"))
    finally:
        publisher.discord.HTTPException = original

    assert len(posted) == 1
    assert posted[0][0].url == "https://a.test/2"


# --------------------------------------------------------------------------- #
# Feed health
# --------------------------------------------------------------------------- #
def test_dead_feed_flagged_after_n_cycles():
    state = State(retention_days=7)
    for _ in range(3):
        state.record_feed_results([
            FeedResult(name="DeadRSS", articles=[], error="HTTP 404"),
            FeedResult(name="AliveRSS", articles=[article()]),
        ])
    dead = [f.name for f in state.unhealthy_feeds(threshold=3)]
    assert dead == ["DeadRSS"]


def test_recovered_feed_resets_the_counter():
    state = State(retention_days=7)
    state.record_feed_results([FeedResult(name="F", articles=[], error="HTTP 500")])
    state.record_feed_results([FeedResult(name="F", articles=[article()])])
    assert state.unhealthy_feeds(threshold=1) == []


# --------------------------------------------------------------------------- #
# CVE extraction
# --------------------------------------------------------------------------- #
def test_valid_cve_extraction():
    cves = extract_cves("See CVE-2026-1234 and cve-2025-99999, both patched.")
    assert cves == ["CVE-2026-1234", "CVE-2025-99999"]


@pytest.mark.parametrize("bogus", ["CVE-0000-0000", "CVE-1990-1234", "CVE-2099-1234"])
def test_bogus_year_rejected(bogus):
    assert extract_cves(bogus) == []


def test_duplicate_cves_removed():
    assert extract_cves("CVE-2026-1234 then again CVE-2026-1234") == ["CVE-2026-1234"]