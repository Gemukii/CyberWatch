import asyncio
import time

import pytest

import run_once
import sources
from pipeline import Pipeline
from run_once import DryRunChannel, PrimingError, run_with_channel
from sources import Article, FeedResult

from helpers import FakeChannel, make_settings


def serving(monkeypatch):
    item = Article(
        title="Vendor patches flaw in product",
        url="https://example.com/a",
        source="Test",
        source_weight=10,
        summary="A long enough description of the vulnerability. " * 8,
        published_ts=time.time(),
    )

    async def fetch(*args, **kwargs):
        return [item], [FeedResult(name="feed", articles=[item])]

    monkeypatch.setattr(sources, "fetch_all_feeds", fetch)


def test_unreadable_history_publishes_nothing(monkeypatch):
    """An empty index would republish the whole retention window."""
    serving(monkeypatch)
    channel = FakeChannel(fail_history=True)
    pipe = Pipeline(make_settings(digest_hour=0))

    with pytest.raises(PrimingError):
        asyncio.run(run_with_channel(pipe, channel, force_digest=True))

    assert channel.sent == []


def test_dry_run_never_reaches_the_inner_channel(monkeypatch):
    serving(monkeypatch)
    inner = FakeChannel()
    dry = DryRunChannel(inner)
    pipe = Pipeline(make_settings(digest_hour=0))

    report = asyncio.run(run_with_channel(pipe, dry, force_digest=True))

    assert report["digest"] == 1
    assert dry.sent
    assert inner.sent == []


def test_failed_cycle_exits_non_zero(monkeypatch):
    """The exit code is what makes GitHub report the failure."""
    async def fetch(*args, **kwargs):
        raise RuntimeError("network down")

    monkeypatch.setattr(sources, "fetch_all_feeds", fetch)
    monkeypatch.setattr(run_once, "settings", make_settings(discord_token=""))

    assert asyncio.run(run_once.run(dry_run=True, force_digest=False)) == 1


def test_clean_cycle_exits_zero(monkeypatch):
    serving(monkeypatch)
    monkeypatch.setattr(run_once, "settings", make_settings(discord_token="", digest_hour=23))

    assert asyncio.run(run_once.run(dry_run=True, force_digest=False)) == 0
