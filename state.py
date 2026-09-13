"""
In-memory anti-duplicate index, primed from Discord history.

No disk writes: Discord acts as persistent storage.
See docs/ARCHITECTURE.md §3.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

log = logging.getLogger(__name__)

# Discreet markers written into embed footers by publisher.py. They let the
# bot rebuild its publication state from Discord alone, with no local file.
DIGEST_MARKER = "#digest"
URGENT_MARKER = "#urgent"
KEV_ESCALATION_MARKER = "#kev-escalation"

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "mc_cid", "mc_eid", "ref", "source",
}

# Absolute cap on messages re-read, regardless of configuration: prevents
# a very old channel from blocking startup for minutes.
HARD_HISTORY_CAP = 5000


def canonical_url(url: str) -> str:
    """Normalizes a URL: lowercase host, no tracking params, no fragment."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return url.strip()
    query = [(k, v) for k, v in parse_qsl(parts.query) if k.lower() not in TRACKING_PARAMS]
    return urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), parts.path.rstrip("/"), urlencode(query), "")
    )


def url_hash(url: str) -> str:
    return hashlib.sha256(canonical_url(url).encode("utf-8")).hexdigest()[:16]


def normalize_title(title: str) -> str:
    """Title stripped down to essentials, for comparing two articles."""
    cleaned = "".join(c.lower() if c.isalnum() or c.isspace() else " " for c in title)
    return " ".join(cleaned.split())


class FeedHealth:
    """
    Health tracking for a single feed.

    A dead feed fails silently: the URL changed, the site shut down, and
    the bot just keeps running without ever surfacing anything. So we count
    consecutive empty cycles to make the outage visible.
    """

    def __init__(self, name: str):
        self.name = name
        self.consecutive_failures = 0
        self.last_error: str | None = None
        self.last_success_ts: float = 0.0
        self.total_articles = 0

    def record(self, count: int, error: str | None) -> None:
        if error or count == 0:
            self.consecutive_failures += 1
            self.last_error = error or "no article returned"
        else:
            self.consecutive_failures = 0
            self.last_error = None
            self.last_success_ts = time.time()
            self.total_articles += count

    def is_unhealthy(self, threshold: int) -> bool:
        return self.consecutive_failures >= threshold


class State:
    """In-memory index of published articles + feed health."""

    def __init__(self, retention_days: int = 7, kev_retro_days: int = 14):
        self.retention_days = retention_days
        self.retention_seconds = retention_days * 86400
        # Separate, usually longer window: a CVE can take days or weeks to
        # land in the KEV catalog after the article about it is published,
        # well past the anti-duplicate window above.
        self.kev_retro_seconds = kev_retro_days * 86400
        self._seen: dict[str, float] = {}                  # url_hash -> timestamp
        self._titles: deque[tuple[str, float]] = deque()   # (normalized title, timestamp)
        self._runs: deque[dict] = deque(maxlen=20)
        self._feeds: dict[str, FeedHealth] = {}
        # cve -> {"url", "title", "source", "ts"}: every CVE seen in a
        # published article, kept around so a later KEV listing can still
        # be caught after the fact (see pending_kev_escalations()).
        self._published_cves: dict[str, dict] = {}
        self._kev_escalated: set[str] = set()   # CVEs already flagged once
        self._primed = False
        self.started_at = time.time()

    # --- Priming from Discord ---
    @property
    def primed(self) -> bool:
        return self._primed

    async def prime_from_channel(self, channel, limit: int = 0, budget=None) -> int:
        """
        Rebuilds the index from messages already published in the channel.

        The read is bounded **by date** (`retention_days` window), not by a
        fixed message count: that's what guarantees the index covers
        exactly the anti-duplicate window, regardless of publishing pace.
        discord.py paginates automatically.

        `limit` is an optional safety cap (0 = no cap). Requires the
        "Read Message History" permission.

        If `budget` is provided, this also restores the last digest date
        and today's urgent-alert count: without it, a 10am restart would
        re-publish the digest already sent at 8am.
        """
        if self._primed:
            # on_ready fires again on every reconnect: without this guard
            # we'd re-read the whole history for nothing.
            log.debug("Index already primed, skipping re-read")
            return 0

        # Bounded by the LONGER of the two windows: KEV retrospective
        # tracking usually needs more days than plain anti-duplicate dedup,
        # and a single history read has to satisfy both.
        window_days = max(self.retention_days, self.kev_retro_seconds / 86400)
        after = datetime.now(tz=timezone.utc) - timedelta(days=window_days)
        effective_limit = min(limit, HARD_HISTORY_CAP) if limit > 0 else HARD_HISTORY_CAP

        found = 0
        scanned = 0
        try:
            async for message in channel.history(
                limit=effective_limit, after=after, oldest_first=False
            ):
                scanned += 1
                for embed in message.embeds:
                    ts = message.created_at.timestamp()
                    footer_text = embed.footer.text if embed.footer and embed.footer.text else ""

                    if not embed.url:
                        # Linkless header: this is what marks an
                        # already-sent digest (see publisher.DIGEST_MARKER).
                        if budget is not None and DIGEST_MARKER in footer_text:
                            budget.note_digest_from_timestamp(ts)
                        continue

                    if budget is not None and URGENT_MARKER in footer_text:
                        budget.note_urgent_from_timestamp(ts)

                    # An escalation alert links back to the original article,
                    # so it still carries a URL — but its footer marks it as
                    # already-sent, so it isn't fired again for the same CVE.
                    if KEV_ESCALATION_MARKER in footer_text:
                        for cve in CVE_RE.findall(footer_text):
                            self._kev_escalated.add(cve.upper())

                    if ts >= time.time() - self.retention_seconds:
                        self._seen[url_hash(embed.url)] = ts
                        raw_title = (embed.author.name if embed.author else None) or embed.title or ""
                        if raw_title:
                            self._titles.append((normalize_title(raw_title), ts))
                        found += 1

                    # CVE field survives outside the (shorter) dedup window:
                    # a vuln can take weeks to reach KEV after its article ran.
                    for field in embed.fields:
                        if field.name != "CVE":
                            continue
                        for cve in CVE_RE.findall(field.value or ""):
                            cve = cve.upper()
                            self._published_cves.setdefault(
                                cve,
                                {
                                    "url": embed.url,
                                    "title": (embed.author.name if embed.author else embed.title) or "",
                                    "ts": ts,
                                },
                            )
        except Exception as exc:
            # Non-blocking failure: worst case, a few articles get
            # re-published once.
            log.warning(
                "Could not prime from history (%s). "
                "Check the 'Read Message History' permission.",
                exc,
            )
            return 0

        # History is walked newest-to-oldest: put the deque back in
        # chronological order so purging works correctly.
        self._titles = deque(sorted(self._titles, key=lambda item: item[1]))
        self._primed = True

        if scanned >= effective_limit:
            log.warning(
                "Hit the %d-message cap while priming: the index may be "
                "incomplete over the %d-day window.",
                effective_limit,
                self.retention_days,
            )
        log.info(
            "Priming: %d articles recovered from %d history messages (%dd)",
            found, scanned, self.retention_days,
        )
        return found

    # --- Deduplication ---
    def _purge(self) -> None:
        """Forgets anything past the retention window."""
        cutoff = time.time() - self.retention_seconds
        for h in [h for h, ts in self._seen.items() if ts < cutoff]:
            del self._seen[h]
        while self._titles and self._titles[0][1] < cutoff:
            self._titles.popleft()

        # Separate, usually longer window for CVE retrospective tracking.
        kev_cutoff = time.time() - self.kev_retro_seconds
        for cve in [c for c, info in self._published_cves.items() if info["ts"] < kev_cutoff]:
            del self._published_cves[cve]
            self._kev_escalated.discard(cve)

    def is_known(self, url: str) -> bool:
        # Purges first: without it, correctness here silently depended on
        # recent_titles() having been called earlier in the same cycle to
        # trigger the purge as a side effect — true in practice today, but
        # fragile to any future reordering.
        self._purge()
        return url_hash(url) in self._seen

    def recent_titles(self, days: int = 5) -> list[str]:
        self._purge()
        cutoff = time.time() - days * 86400
        return [title for title, ts in self._titles if ts >= cutoff]

    def mark_published(
        self, url: str, title: str, source: str = "", severity: str = "", cves: list[str] | None = None
    ) -> None:
        now = time.time()
        self._seen[url_hash(url)] = now
        self._titles.append((normalize_title(title), now))
        for cve in cves or []:
            cve = cve.upper()
            self._published_cves.setdefault(cve, {"url": url, "title": title, "ts": now})

    # --- KEV retrospective escalation ---
    def pending_kev_escalations(self, kev_cves: list[str]) -> list[dict]:
        """
        Published CVEs that have since entered the KEV catalog and haven't
        been escalated yet.

        `kev_cves` is the subset of tracked CVEs the caller has already
        confirmed are in KEV right now (via Enricher.in_kev) — this method
        only filters out the ones already flagged, it doesn't re-check KEV
        itself.
        """
        pending = []
        for cve in kev_cves:
            cve = cve.upper()
            info = self._published_cves.get(cve)
            if info and cve not in self._kev_escalated:
                pending.append({"cve": cve, **info})
        return pending

    def tracked_cves(self) -> list[str]:
        """All CVEs currently tracked for retrospective KEV escalation."""
        self._purge()
        return list(self._published_cves)

    def record_kev_escalation(self, cve: str) -> None:
        self._kev_escalated.add(cve.upper())

    # --- Feed health ---
    def record_feed_results(self, results) -> None:
        for result in results:
            health = self._feeds.setdefault(result.name, FeedHealth(result.name))
            health.record(len(result.articles), result.error)

    def unhealthy_feeds(self, threshold: int) -> list[FeedHealth]:
        return [f for f in self._feeds.values() if f.is_unhealthy(threshold)]

    def feed_report(self, threshold: int) -> list[str]:
        """Per-feed status lines, for /cyber-sources."""
        lines = []
        for health in sorted(self._feeds.values(), key=lambda f: f.name):
            if health.is_unhealthy(threshold):
                icon, detail = "🔴", f"{health.consecutive_failures} cycles with no article"
                if health.last_error:
                    detail += f" — {health.last_error[:60]}"
            elif health.consecutive_failures:
                icon, detail = "🟡", f"{health.consecutive_failures} empty cycle(s)"
            else:
                icon, detail = "🟢", f"{health.total_articles} articles seen"
            lines.append(f"{icon} **{health.name}** — {detail}")
        return lines

    # --- Statistics ---
    def log_run(
        self,
        fetched: int = 0,
        queued: int = 0,
        queue_size: int = 0,
        urgent: int = 0,
        digest: int = 0,
        posted: int = 0,
        deferred: int = 0,
        kev_escalations: int = 0,
        error: str | None = None,
    ) -> None:
        """Records a cycle's outcome. Counters separate collection
        (continuous) from publishing (arbitrated)."""
        self._runs.append(
            {
                "started_at": int(time.time()),
                "fetched": fetched,
                "queued": queued,
                "queue_size": queue_size,
                "urgent": urgent,
                "digest": digest,
                "posted": posted,
                "deferred": deferred,
                "kev_escalations": kev_escalations,
                "error": error,
            }
        )

    def last_run(self) -> dict | None:
        return self._runs[-1] if self._runs else None

    def count_published(self, days: int = 7) -> int:
        cutoff = time.time() - days * 86400
        return sum(1 for ts in self._seen.values() if ts >= cutoff)

    def memory_footprint(self) -> str:
        approx = (
            len(self._seen) * 40
            + sum(len(t) for t, _ in self._titles)
            + len(self._published_cves) * 80
        )
        return f"{approx / 1024:.1f} KB"

    def uptime(self) -> str:
        seconds = int(time.time() - self.started_at)
        days, rest = divmod(seconds, 86400)
        hours, minutes = divmod(rest // 60, 60)
        return f"{days}d {hours}h" if days else f"{hours}h {minutes}min"