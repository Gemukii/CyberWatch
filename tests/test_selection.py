"""
Tests for daily arbitration: candidate queue, budget, urgent alerts.

These tests protect the project's core invariant: **at most N articles
per day**, except for confirmed urgent alerts, and never padding to hit
the quota.
"""

from datetime import datetime, timedelta
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest

from selection import CandidateQueue, DailyBudget, is_urgent
from sources import Article

TZ = ZoneInfo("Europe/Paris")


def make_article(title="Title", url="https://ex.com/a", score=10, **kw):
    article = Article(title=title, url=url, source=kw.pop("source", "S"))
    article.score = score
    article.cves = kw.pop("cves", [])
    article.kev_cves = kw.pop("kev_cves", [])
    article.kev_ransomware = kw.pop("kev_ransomware", False)
    article.epss_max = kw.pop("epss_max", None)
    return article


def make_settings(**overrides):
    base = dict(
        urgent_epss_threshold=0.7,
        urgent_score_threshold=30,
        urgent_daily_max=3,
        daily_quota=4,
        digest_floor_score=7,
        digest_min_articles=2,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


# --------------------------------------------------------------------------- #
# Candidate queue
# --------------------------------------------------------------------------- #
def test_articles_from_different_cycles_compete_together():
    """The core of the change: a 2pm article must be able to beat a 3am
    article, instead of being dropped for arriving after it."""
    queue = CandidateQueue()
    queue.add(make_article("3am article", "https://ex.com/night", score=14), "k1")
    queue.add(make_article("2pm article", "https://ex.com/afternoon", score=28), "k2")

    best = queue.ranked()[0][1]
    assert best.title == "2pm article"


def test_duplicate_does_not_inflate_the_queue():
    queue = CandidateQueue()
    assert queue.add(make_article(score=10), "k1") is True
    assert queue.add(make_article(score=10), "k1") is False
    assert len(queue) == 1


def test_score_refreshed_if_article_gains_severity():
    """A CVE can enter the KEV catalog between two cycles: the candidate
    must be re-ranked with its new score, not stuck with the old one."""
    queue = CandidateQueue()
    queue.add(make_article(score=10), "k1")
    queue.add(make_article(score=35), "k1")  # same URL, score re-evaluated
    assert queue.ranked()[0][1].score == 35


def test_expired_candidate_leaves_the_queue():
    queue = CandidateQueue(ttl_hours=1)
    queue.add(make_article(), "k1")
    queue._items["k1"] = (queue._items["k1"][0], 0.0)  # very old entry
    assert queue.purge() == 1
    assert len(queue) == 0


def test_publishing_removes_from_the_queue():
    queue = CandidateQueue()
    queue.add(make_article(url="https://ex.com/1"), "k1")
    queue.add(make_article(url="https://ex.com/2"), "k2")
    queue.remove(["k1"])
    assert len(queue) == 1


# --------------------------------------------------------------------------- #
# Daily budget
# --------------------------------------------------------------------------- #
def test_digest_not_due_before_the_hour():
    budget = DailyBudget("Europe/Paris", digest_hour=8)
    assert budget.digest_due(datetime(2026, 8, 23, 7, 30, tzinfo=TZ)) is False


def test_digest_due_at_the_scheduled_hour():
    budget = DailyBudget("Europe/Paris", digest_hour=8)
    assert budget.digest_due(datetime(2026, 8, 23, 8, 5, tzinfo=TZ)) is True


def test_digest_sent_only_once_a_day():
    budget = DailyBudget("Europe/Paris", digest_hour=8)
    moment = datetime(2026, 8, 23, 8, 5, tzinfo=TZ)
    budget.note_digest(moment)
    assert budget.digest_due(moment) is False
    assert budget.digest_due(datetime(2026, 8, 23, 20, 0, tzinfo=TZ)) is False
    # The next day, it's due again.
    assert budget.digest_due(datetime(2026, 8, 24, 8, 1, tzinfo=TZ)) is True


def test_digest_catches_up_after_downtime():
    """VPS down at 8am: the digest must go out on restart, not be skipped
    for the day."""
    budget = DailyBudget("Europe/Paris", digest_hour=8)
    assert budget.digest_due(datetime(2026, 8, 23, 15, 0, tzinfo=TZ)) is True


def test_restart_does_not_republish_the_digest():
    """State is re-read from Discord: a 10am restart must not resend the
    digest already published at 8am."""
    budget = DailyBudget("Europe/Paris", digest_hour=8)
    sent_at_8am = datetime(2026, 8, 23, 8, 0, tzinfo=TZ).timestamp()
    budget.note_digest_from_timestamp(sent_at_8am)
    assert budget.digest_due(datetime(2026, 8, 23, 10, 0, tzinfo=TZ)) is False


def test_urgent_quota_bounds_the_day():
    budget = DailyBudget("Europe/Paris", digest_hour=8)
    assert budget.urgent_slots_left(3) == 3
    budget.note_urgent(2)
    assert budget.urgent_slots_left(3) == 1
    budget.note_urgent(5)
    assert budget.urgent_slots_left(3) == 0  # never negative


# --------------------------------------------------------------------------- #
# Urgency criteria
# --------------------------------------------------------------------------- #
def test_kev_triggers_urgency():
    article = make_article(score=15, cves=["CVE-2026-1"], kev_cves=["CVE-2026-1"])
    urgent, reason = is_urgent(article, make_settings())
    assert urgent and "KEV" in reason


def test_kev_ransomware_refines_the_reason():
    article = make_article(
        cves=["CVE-2026-1"], kev_cves=["CVE-2026-1"], kev_ransomware=True
    )
    urgent, reason = is_urgent(article, make_settings())
    assert urgent and "ransomware" in reason


def test_high_epss_triggers_urgency():
    article = make_article(score=15, cves=["CVE-2026-1"], epss_max=0.85)
    urgent, reason = is_urgent(article, make_settings())
    assert urgent and "EPSS" in reason


def test_moderate_epss_does_not_trigger():
    article = make_article(score=15, cves=["CVE-2026-1"], epss_max=0.3)
    urgent, _ = is_urgent(article, make_settings())
    assert urgent is False


def test_exceptional_score_covers_cve_less_stories():
    """A major compromise with no CVE (supply chain, massive breach) must
    still be catchable."""
    article = make_article(score=32)
    urgent, reason = is_urgent(article, make_settings())
    assert urgent and "score" in reason


def test_ordinary_article_waits_for_the_digest():
    article = make_article(score=18, cves=["CVE-2026-1"], epss_max=0.1)
    urgent, _ = is_urgent(article, make_settings())
    assert urgent is False


# --------------------------------------------------------------------------- #
# Central invariant: the quota is a cap, never a target
# --------------------------------------------------------------------------- #
def _simulate_digest(scores, settings):
    """
    Reproduces the digest arbitration as implemented in bot.py.

    Selection is RELATIVE: take the top N of the day, with a floor that
    only screens out off-topic articles, and an anti-silence guarantee
    that rescues the best available if the floor leaves nothing.
    """
    queue = CandidateQueue()
    for index, score in enumerate(scores):
        queue.add(make_article(f"A{index}", f"https://ex.com/{index}", score=score), f"k{index}")
    ranked = [a for _, a in queue.ranked()]
    chosen = [a for a in ranked if a.score >= settings.digest_floor_score][
        : settings.daily_quota
    ]
    target = min(settings.digest_min_articles, settings.daily_quota)
    if len(chosen) < target and ranked:
        remainder = [a for a in ranked if a not in chosen]
        chosen += remainder[: target - len(chosen)]
    return chosen


def test_never_more_than_the_quota():
    settings = make_settings(daily_quota=3)
    assert len(_simulate_digest([30, 28, 25, 22, 20, 18, 15, 14, 13], settings)) == 3


def test_the_best_are_chosen():
    settings = make_settings(daily_quota=2)
    chosen = _simulate_digest([14, 31, 13, 27], settings)
    assert [a.score for a in chosen] == [31, 27]


def test_relative_selection_publishes_even_with_average_scores():
    """
    The core of the model: a day with no major story still publishes the
    best of what's available. A fixed threshold would have produced silence.
    """
    settings = make_settings(daily_quota=4)
    chosen = _simulate_digest([11, 10, 9, 8, 7], settings)
    assert [a.score for a in chosen] == [11, 10, 9, 8]


def test_anti_silence_guarantee_rescues_below_the_floor():
    """Very quiet day: DIGEST_MIN_ARTICLES still gets published."""
    settings = make_settings(daily_quota=4, digest_min_articles=2)
    chosen = _simulate_digest([5, 4, 3], settings)
    assert [a.score for a in chosen] == [5, 4]


def test_silence_possible_when_disabled():
    """With DIGEST_MIN_ARTICLES=0, silence stays possible."""
    settings = make_settings(daily_quota=4, digest_min_articles=0)
    assert _simulate_digest([5, 4, 3], settings) == []


def test_empty_queue_publishes_nothing():
    """The only default case of silence: nothing was collected."""
    assert _simulate_digest([], make_settings()) == []


def test_quota_overrides_the_guarantee():
    """DIGEST_MIN_ARTICLES can never push past DAILY_QUOTA."""
    settings = make_settings(daily_quota=1, digest_min_articles=3)
    assert len(_simulate_digest([30, 28, 25], settings)) == 1


@pytest.mark.parametrize("quota,floor,minimum,scores,expected", [
    (4, 7, 2, [40, 35, 30, 25, 20], 4),   # busy day: capped
    (4, 7, 2, [40], 1),                   # a single story: no padding
    (4, 7, 2, [11, 10], 2),               # average scores: still publishes
    (4, 7, 2, [5, 4], 2),                 # below the floor: rescued
    (4, 7, 0, [5, 4], 0),                 # rescue disabled: silence
    (2, 7, 2, [25, 22, 21], 2),           # tight quota
])
def test_daily_volume_bounded(quota, floor, minimum, scores, expected):
    settings = make_settings(
        daily_quota=quota, digest_floor_score=floor, digest_min_articles=minimum
    )
    assert len(_simulate_digest(scores, settings)) == expected