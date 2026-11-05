import asyncio
import sys
import time

import run_once
import sources
from sources import Article, FeedResult

from helpers import make_settings


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


def test_failed_cycle_exits_non_zero(monkeypatch):
    """The exit code is what makes GitHub report the failure."""
    async def fetch(*args, **kwargs):
        raise RuntimeError("network down")

    monkeypatch.setattr(sources, "fetch_all_feeds", fetch)
    monkeypatch.setattr(run_once, "settings", make_settings(discord_token=""))

    assert asyncio.run(run_once.run(False, False, offline=True)) == 1


FEED = [{"name": "feed", "url": "https://example.com/rss", "weight": 1}]


def test_dry_run_fails_without_a_token(monkeypatch, capsys):
    """A dry run has to prove the token works, not skip Discord and pass."""
    serving(monkeypatch)
    monkeypatch.setattr(run_once, "settings", make_settings(discord_token="", feeds=FEED))
    monkeypatch.setattr(sys, "argv", ["run_once.py", "--dry-run"])

    assert run_once.main() == 2
    assert "DISCORD_TOKEN" in capsys.readouterr().err


def test_offline_needs_no_discord_settings(monkeypatch):
    serving(monkeypatch)
    monkeypatch.setattr(
        run_once,
        "settings",
        make_settings(discord_token="", channel_id=0, feeds=FEED, digest_hour=23),
    )
    monkeypatch.setattr(sys, "argv", ["run_once.py", "--offline"])

    assert run_once.main() == 0


def test_run_reports_what_it_did_on_github(monkeypatch, tmp_path):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    serving(monkeypatch)
    monkeypatch.setattr(run_once, "settings", make_settings(discord_token="", digest_hour=0))

    assert asyncio.run(run_once.run(False, True, offline=True)) == 0

    text = summary.read_text(encoding="utf-8")
    assert "| Mode | offline |" in text
    assert "| Published | 1 |" in text
