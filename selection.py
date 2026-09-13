"""
Candidate queue, daily quotas, urgent/digest arbitration.

Articles aren't published on arrival: they compete against each other and
only the best of the day make it out. See docs/ARCHITECTURE.md §1.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

log = logging.getLogger(__name__)


class CandidateQueue:
    """Queue of articles awaiting arbitration, deduplicated by URL."""

    def __init__(self, ttl_hours: int = 36):
        self.ttl_seconds = ttl_hours * 3600
        self._items: dict[str, tuple[object, float]] = {}  # url_hash -> (article, ts)

    def __len__(self) -> int:
        return len(self._items)

    def add(self, article, key: str) -> bool:
        """
        Adds or updates a candidate. Returns True if it's new.

        An article already in the queue has its score refreshed: the
        content may have been enriched in the meantime (added to KEV, EPSS
        score going up), and it's the most recent score that should decide.
        """
        is_new = key not in self._items
        if not is_new:
            previous, first_seen = self._items[key]
            if getattr(article, "score", 0) >= getattr(previous, "score", 0):
                self._items[key] = (article, first_seen)  # keep the original entry time
            return False
        self._items[key] = (article, time.time())
        return True

    def purge(self, max_age_hours: int | None = None) -> int:
        """Removes candidates too old to still be newsworthy."""
        ttl = (max_age_hours * 3600) if max_age_hours else self.ttl_seconds
        cutoff = time.time() - ttl
        expired = [k for k, (_, ts) in self._items.items() if ts < cutoff]
        for key in expired:
            del self._items[key]
        return len(expired)

    def remove(self, keys: list[str]) -> None:
        for key in keys:
            self._items.pop(key, None)

    def ranked(self) -> list[tuple[str, object]]:
        """Candidates sorted by descending score, best first."""
        return [
            (key, article)
            for key, (article, _) in sorted(
                self._items.items(),
                key=lambda item: getattr(item[1][0], "score", 0),
                reverse=True,
            )
        ]

    def top_scores(self, count: int = 5) -> list[int]:
        return [getattr(a, "score", 0) for _, a in self.ranked()[:count]]


class DailyBudget:
    """
    Tracks what's been published today and decides when the digest is due.

    The day is computed in the user's timezone, not UTC: a digest "at 8am"
    must land at 8am local time, including during daylight saving shifts.
    """

    def __init__(self, timezone_name: str = "Europe/Paris", digest_hour: int = 8):
        try:
            self.tz = ZoneInfo(timezone_name)
        except Exception:
            log.warning("Unknown timezone %r, falling back to UTC", timezone_name)
            self.tz = timezone.utc
        self.digest_hour = digest_hour
        self._last_digest_date: str | None = None
        # Keyed by (kind, date): shared trimming logic for every daily
        # counter (urgent alerts, KEV escalations, and whatever comes next)
        # instead of one hand-duplicated dict per kind.
        self._daily_counts: dict[tuple[str, str], int] = {}

    # ------------------------------------------------------------------ #
    def now(self) -> datetime:
        return datetime.now(tz=self.tz)

    def today_key(self, moment: datetime | None = None) -> str:
        return (moment or self.now()).strftime("%Y-%m-%d")

    def _count_today(self, kind: str, moment: datetime | None = None) -> int:
        return self._daily_counts.get((kind, self.today_key(moment)), 0)

    def _note(self, kind: str, count: int = 1, moment: datetime | None = None) -> None:
        key = (kind, self.today_key(moment))
        self._daily_counts[key] = self._daily_counts.get(key, 0) + count
        # Keep only a few days of history per kind.
        dates = sorted({d for k, d in self._daily_counts if k == kind})
        for old in dates[:-7]:
            del self._daily_counts[(kind, old)]

    # --- Digest ---
    @property
    def last_digest_date(self) -> str | None:
        return self._last_digest_date

    def note_digest(self, moment: datetime | None = None) -> None:
        self._last_digest_date = self.today_key(moment)

    def note_digest_from_timestamp(self, ts: float) -> None:
        """Used during startup priming, by re-reading Discord history."""
        date_key = self.today_key(datetime.fromtimestamp(ts, tz=self.tz))
        if self._last_digest_date is None or date_key > self._last_digest_date:
            self._last_digest_date = date_key

    def digest_due(self, moment: datetime | None = None) -> bool:
        """
        True if today's digest should go out now.

        Publishes as soon as the target hour is reached or passed: if the
        VPS was down at 8am, the digest goes out on the first cycle after
        restart instead of being skipped for the day.
        """
        moment = moment or self.now()
        if moment.hour < self.digest_hour:
            return False
        return self._last_digest_date != self.today_key(moment)

    def next_digest_at(self, moment: datetime | None = None) -> datetime:
        moment = moment or self.now()
        target = moment.replace(
            hour=self.digest_hour, minute=0, second=0, microsecond=0
        )
        if moment >= target and self._last_digest_date == self.today_key(moment):
            target += timedelta(days=1)
        elif moment >= target:
            return moment  # overdue: due immediately
        return target

    # --- Urgent alerts ---
    def urgent_count_today(self, moment: datetime | None = None) -> int:
        return self._count_today("urgent", moment)

    def note_urgent(self, count: int = 1, moment: datetime | None = None) -> None:
        self._note("urgent", count, moment)

    def note_urgent_from_timestamp(self, ts: float) -> None:
        self._note("urgent", 1, datetime.fromtimestamp(ts, tz=self.tz))

    def urgent_slots_left(self, daily_max: int) -> int:
        return max(0, daily_max - self.urgent_count_today())

    # --- KEV retrospective escalations ---
    def kev_escalation_count_today(self, moment: datetime | None = None) -> int:
        return self._count_today("kev_escalation", moment)

    def note_kev_escalation(self, count: int = 1, moment: datetime | None = None) -> None:
        self._note("kev_escalation", count, moment)

    def kev_escalation_slots_left(self, daily_max: int) -> int:
        return max(0, daily_max - self.kev_escalation_count_today())


def is_urgent(article, settings) -> tuple[bool, str]:
    """
    Decides whether an article warrants immediate publication, outside the quota.

    Criteria rely on authoritative sources rather than journalistic
    language: an alert that fires too often stops being an alert.

    Returns (urgent, human-readable reason).
    """
    # 1. Listed in the CISA KEV catalog = confirmed exploitation in the
    #    wild. The strongest signal available for free.
    if getattr(article, "kev_cves", None):
        cve = article.kev_cves[0]
        if getattr(article, "kev_ransomware", False):
            return True, f"{cve} in the CISA KEV catalog — known ransomware campaign"
        return True, f"{cve} in the CISA KEV catalog — confirmed exploitation"

    # 2. Very high EPSS: exploitation judged highly likely within 30 days.
    epss = getattr(article, "epss_max", None)
    if epss is not None and epss >= settings.urgent_epss_threshold:
        return True, f"EPSS {epss:.0%} — exploitation highly likely within 30 days"

    # 3. Safety net: exceptional score, well above the usual threshold.
    #    Covers CVE-less stories (major compromise, supply-chain incident)
    #    that no catalog would otherwise catch.
    if getattr(article, "score", 0) >= settings.urgent_score_threshold:
        return True, f"exceptional relevance score ({article.score})"

    return False, ""