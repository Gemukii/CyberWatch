import asyncio
import time

import pytest

import publisher
import sources
from pipeline import Pipeline
from filters import score_article
from selection import distinct_stories, is_urgent
from sources import Article, FeedResult
from state import url_hash
from summarizer import QuotaExceeded, Summary

from helpers import FakeChannel, make_settings, message

CVE = "CVE-2026-1111"


def article(title="Vendor patches flaw in product", url="https://example.com/a", score=20):
    return Article(
        title=title,
        url=url,
        source="Test",
        source_weight=10,
        summary="A long enough description of the vulnerability. " * 8,
        published_ts=time.time(),
        score=score,
    )


@pytest.fixture
def no_feeds(monkeypatch):
    """A quiet cycle: the feeds answer, but carry nothing new."""
    async def fetch(*args, **kwargs):
        return [], [FeedResult(name="feed", articles=[])]

    monkeypatch.setattr(sources, "fetch_all_feeds", fetch)


def serving(monkeypatch, articles):
    async def fetch(*args, **kwargs):
        return list(articles), [FeedResult(name="feed", articles=list(articles))]

    monkeypatch.setattr(sources, "fetch_all_feeds", fetch)


def primed(channel, settings=None) -> Pipeline:
    pipe = Pipeline(settings or make_settings())
    asyncio.run(pipe.state.prime_from_channel(channel, budget=pipe.budget))
    return pipe


def load_kev(pipe, *cves):
    """Stands in for the catalog download."""
    async def ensure():
        pipe.enricher._kev = {cve: False for cve in cves}

    pipe.enricher.ensure_kev = ensure


def test_kev_escalation_is_not_sent_again_by_the_next_run(no_feeds):
    """Each run starts from Discord history alone."""
    published = publisher.build_embed(
        Article(title="t", url="https://example.com/a", source="s", cves=[CVE]),
        Summary(title="t", bullets=["b"], severity="High", cves=[CVE]),
    )
    channel = FakeChannel([message(published)])

    first = primed(channel)
    load_kev(first, CVE)
    report = asyncio.run(first.run_cycle(channel))
    assert report["kev_escalations"] == 1

    second = primed(channel)
    load_kev(second, CVE)
    report = asyncio.run(second.run_cycle(channel))
    assert report["kev_escalations"] == 0


def test_kev_daily_cap_holds_across_runs(no_feeds):
    settings = make_settings(kev_retro_max_per_day=1)
    cves = ["CVE-2026-0001", "CVE-2026-0002"]
    published = publisher.build_embed(
        Article(title="t", url="https://example.com/a", source="s", cves=cves),
        Summary(title="t", bullets=["b"], severity="High", cves=cves),
    )
    channel = FakeChannel([message(published)])

    first = primed(channel, settings)
    load_kev(first, *cves)
    assert asyncio.run(first.run_cycle(channel))["kev_escalations"] == 1

    second = primed(channel, settings)
    load_kev(second, *cves)
    assert asyncio.run(second.run_cycle(channel))["kev_escalations"] == 0


def test_kev_catalog_is_loaded_on_a_quiet_cycle(no_feeds):
    channel = FakeChannel()
    pipe = primed(channel)
    pipe.state.mark_published("https://example.com/a", "t", cves=[CVE])
    calls = []

    async def ensure():
        calls.append(True)

    pipe.enricher.ensure_kev = ensure
    asyncio.run(pipe.run_cycle(channel))

    assert calls


def test_failed_digest_stays_due(monkeypatch):
    serving(monkeypatch, [article()])
    settings = make_settings(digest_hour=0)
    pipe = primed(FakeChannel(), settings)
    channel = FakeChannel(fail_send=True)

    report = asyncio.run(pipe.run_cycle(channel))

    assert report["digest"] == 0
    assert pipe.budget.digest_due()


def test_empty_digest_is_not_retried_later_the_same_day(no_feeds):
    settings = make_settings(digest_hour=0)
    channel = FakeChannel()
    pipe = primed(channel, settings)

    asyncio.run(pipe.run_cycle(channel))

    assert not pipe.budget.digest_due()


def test_published_article_leaves_the_queue(monkeypatch):
    item = article()
    serving(monkeypatch, [item])
    settings = make_settings(digest_hour=0)
    channel = FakeChannel()
    pipe = primed(channel, settings)

    report = asyncio.run(pipe.run_cycle(channel))

    assert report["digest"] == 1
    assert pipe.state.is_known(item.url)
    assert url_hash(item.url) not in dict(pipe.queue.ranked())


def kev_article(url, score=30, cve=CVE):
    item = article(title=f"Story at {url}", url=url, score=score)
    item.cves = [cve]
    item.kev_cves = [cve]
    return item


def queued(pipe, *articles):
    for item in articles:
        pipe.queue.add(item, url_hash(item.url))


def test_one_cve_covered_by_two_outlets_is_one_alert(no_feeds):
    channel = FakeChannel()
    pipe = primed(channel, make_settings(digest_hour=23))
    queued(pipe, kev_article("https://a.example/1", 40), kev_article("https://b.example/2", 20))
    load_kev(pipe, CVE)

    report = asyncio.run(pipe.run_cycle(channel))

    assert report["urgent"] == 1
    assert [e.url for e in channel.sent if e.url] == ["https://a.example/1"]


def test_second_outlet_is_not_alerted_on_the_next_run(no_feeds):
    settings = make_settings(digest_hour=23)
    channel = FakeChannel()
    first = primed(channel, settings)
    queued(first, kev_article("https://a.example/1"))
    load_kev(first, CVE)
    asyncio.run(first.run_cycle(channel))

    second = primed(channel, settings)
    queued(second, kev_article("https://b.example/2"))
    load_kev(second, CVE)
    report = asyncio.run(second.run_cycle(channel))

    assert report["urgent"] == 0


def test_cve_published_as_kev_is_never_escalated(no_feeds):
    """It was reported as exploited from the start."""
    settings = make_settings(digest_hour=23)
    channel = FakeChannel()
    same_run = primed(channel, settings)
    queued(same_run, kev_article("https://a.example/1"))
    load_kev(same_run, CVE)
    asyncio.run(same_run.run_cycle(channel))
    assert same_run.state.pending_kev_escalations([CVE]) == []

    next_run = primed(channel, settings)
    load_kev(next_run, CVE)
    report = asyncio.run(next_run.run_cycle(channel))

    assert report["kev_escalations"] == 0


def test_articles_without_cve_are_never_merged():
    first, second = article(url="https://a.example/1"), article(url="https://b.example/2")

    assert distinct_stories([first, second], ["CVE-2026-0001"]) == [first, second]


def test_article_with_a_new_cve_stays():
    item = article()
    item.cves = [CVE, "CVE-2026-2222"]

    assert distinct_stories([item], [CVE]) == [item]


def test_reported_exploitation_on_a_watched_product_is_urgent():
    item = Article(title="Fortinet zero-day", url="https://example.com/z", source="Test")
    score_article(item, watchlist=["fortinet"])

    urgent, reason = is_urgent(item, make_settings())

    assert urgent
    assert "fortinet" in reason


def test_reported_exploitation_elsewhere_waits_for_the_digest():
    item = Article(title="Fortinet zero-day", url="https://example.com/z", source="Test")
    score_article(item, watchlist=["cisco"])

    assert is_urgent(item, make_settings()) == (False, "")


def refusing_ai(monkeypatch, pipe):
    """Gemini gives up on every article, as it does when out of quota."""
    async def refuse(session, item):
        raise QuotaExceeded("Gemini unreachable", status="HTTP 429")

    monkeypatch.setattr(pipe.summarizer, "_summarize_one", refuse)


def test_digest_goes_out_without_ai_when_gemini_refuses(monkeypatch):
    serving(monkeypatch, [article()])
    settings = make_settings(ai_provider="gemini", digest_hour=0, enable_urgent=False)
    channel = FakeChannel()
    pipe = primed(channel, settings)
    refusing_ai(monkeypatch, pipe)

    report = asyncio.run(pipe.run_cycle(channel))

    assert report["digest"] == 1
    assert report["degraded"] == 1
    assert report["deferred"] == 0
    assert "without AI" in channel.sent[0].description
    assert not pipe.budget.digest_due()
    assert pipe.summarizer.last_failure == "gemini: HTTP 429"


def test_digest_can_still_wait_for_the_ai(monkeypatch):
    serving(monkeypatch, [article()])
    settings = make_settings(
        ai_provider="gemini", digest_hour=0, digest_degrade_on_quota=False
    )
    channel = FakeChannel()
    pipe = primed(channel, settings)
    refusing_ai(monkeypatch, pipe)

    report = asyncio.run(pipe.run_cycle(channel))

    assert report["digest"] == 0
    assert report["deferred"] == 1
    assert pipe.budget.digest_due()


def test_urgent_alert_waits_for_the_ai(monkeypatch):
    serving(monkeypatch, [article()])
    settings = make_settings(
        ai_provider="gemini", digest_hour=23, urgent_score_threshold=1
    )
    channel = FakeChannel()
    pipe = primed(channel, settings)
    pipe.budget.note_digest()
    refusing_ai(monkeypatch, pipe)

    report = asyncio.run(pipe.run_cycle(channel))

    assert report["urgent"] == 0
    assert report["deferred"] == 1
    assert channel.sent == []


def summary(severity="High", generated_by="gemini"):
    return Summary(title="A title", bullets=["A point"], severity=severity, generated_by=generated_by)


def test_urgent_reason_comes_first_and_footer_stays_short():
    item = article()
    item.category = "Vulnerability"
    item.category_tags = ["RCE"]
    item.signals = ["zero-day"]

    embed = publisher.build_embed(item, summary(), urgent_reason="in the KEV catalog")

    assert embed.fields[0].value == "in the KEV catalog"
    assert [f.name for f in embed.fields[1:3]] == ["Severity", "Category"]
    assert embed.footer.text == "Score 20 · sig:zero-day · #urgent"


def test_header_lists_what_follows():
    embed = publisher.build_header_embed(
        [(article(), summary("Critical"))], "gemini", candidates=9
    )

    assert "out of 9 candidates" in embed.description
    assert "🔴 A title" in embed.description
    assert "without AI" not in embed.description
    assert embed.footer.text.endswith("#digest")
