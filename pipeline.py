"""
The watch cycle, independent of how it is launched.

bot.py runs it from a resident Discord client, run_once.py from a one-shot
job. Both hand it a channel: this module never owns a connection.
"""

from __future__ import annotations

import asyncio
import logging
import time

import discord

import feedback as feedback_mod
import filters
import publisher
import selection as selection_mod
import sources
import state as state_mod
from enrichment import Enricher
from selection import CandidateQueue, DailyBudget
from state import State
from summarizer import Summarizer

log = logging.getLogger("cyberwatch")


class Pipeline:
    def __init__(self, settings):
        self.settings = settings
        self.state = State(
            retention_days=settings.retention_days,
            kev_retro_days=settings.kev_retro_days,
        )
        self.summarizer = Summarizer(settings)
        self.enricher = Enricher(settings)
        self.queue = CandidateQueue(ttl_hours=settings.candidate_ttl_hours)
        self.budget = DailyBudget(
            timezone_name=settings.timezone_name,
            digest_hour=settings.digest_hour,
        )
        # Weights learned from 👍/👎 reactions. Recomputed periodically from
        # Discord history, never stored: see feedback.py.
        self.learned = feedback_mod.LearnedWeights(
            min_votes=settings.feedback_min_votes,
            max_adjustment=settings.feedback_max_adjustment,
        )
        self._feedback_refreshed_at = 0.0
        self.failed_feeds: list[str] = []
        # Prevents two simultaneous cycles (auto loop + manual command).
        self.cycle_lock = asyncio.Lock()

    async def refresh_feedback(self, channel, force: bool = False) -> bool:
        """
        Recomputes learned weights if the cache has expired.

        Re-reading history costs Discord API calls: this only runs once per
        `FEEDBACK_TTL_HOURS`, not every cycle.
        """
        s = self.settings
        if not s.enable_feedback or channel is None:
            return False
        if not force and (time.time() - self._feedback_refreshed_at) < s.feedback_ttl_hours * 3600:
            return False
        self.learned = await feedback_mod.collect_feedback(
            channel,
            lookback_days=s.feedback_lookback_days,
            min_votes=s.feedback_min_votes,
            max_adjustment=s.feedback_max_adjustment,
            message_limit=s.feedback_message_limit,
        )
        self._feedback_refreshed_at = time.time()
        return True

    async def collect(self, report: dict) -> list:
        """
        Free step: collects, filters, enriches, and feeds the candidate queue.
        No AI call happens here, so it can run every hour at no cost.
        """
        s = self.settings
        articles, feed_results = await sources.fetch_all_feeds(
            s.feeds, s.max_age_hours, s.user_agent, s.http_timeout
        )
        self.state.record_feed_results(feed_results)
        self.failed_feeds = [r.name for r in feed_results if r.error]
        report["fetched"] = len(articles)

        unhealthy = self.state.unhealthy_feeds(s.feed_failure_threshold)
        if unhealthy:
            log.warning("Feeds down: %s", ", ".join(f.name for f in unhealthy))

        if not articles:
            return []

        # Pre-filter on title + RSS summary, lowered threshold: keeps margin
        # before the network-costly steps.
        shortlist = filters.select_articles(
            articles,
            self.state,
            min_score=max(1, s.min_score - 3),
            similarity=s.dedup_similarity,
            limit=s.shortlist_limit,
            watchlist=s.watchlist,
            watchlist_weight=s.watchlist_weight,
        )
        if not shortlist:
            return []

        if s.fetch_fulltext:
            await sources.enrich_with_fulltext(
                shortlist, s.user_agent, s.http_timeout, s.fulltext_max_chars
            )

        # KEV / EPSS enrichment, then re-scoring on the full data.
        await self.enricher.enrich(shortlist)
        for article in shortlist:
            article.score, article.reasons = filters.score_article(
                article,
                feedback=self.learned if s.enable_feedback else None,
                watchlist=s.watchlist,
                watchlist_weight=s.watchlist_weight,
            )

        retained = [a for a in shortlist if a.score >= s.min_score]

        # A candidate already in the queue has its score refreshed: a CVE can
        # enter KEV between two cycles.
        added = 0
        for article in retained:
            if self.queue.add(article, state_mod.url_hash(article.url)):
                added += 1
        self.queue.purge(s.candidate_ttl_hours)

        report["queued"] = added
        report["queue_size"] = len(self.queue)
        log.info(
            "Collection: %d articles -> %d queued (%d new, queue = %d)",
            len(articles), len(retained), added, len(self.queue),
        )
        return retained

    async def publish_selection(
        self,
        channel: discord.abc.Messageable,
        chosen: list,
        report: dict,
        urgent_reasons: dict[str, str] | None = None,
        candidates: int | None = None,
        degrade: bool | None = None,
    ) -> int:
        """
        Summarizes then publishes an already-arbitrated selection, and removes
        the actually-published articles from the queue.
        """
        if not chosen:
            return 0

        s = self.settings
        log.info("Summarizing %d article(s) via %s...", len(chosen), s.ai_provider)
        summarized, deferred = await self.summarizer.summarize_many(chosen, degrade=degrade)
        report["deferred"] = report.get("deferred", 0) + len(deferred)

        posted = await publisher.publish(
            channel,
            summarized,
            s.ai_provider,
            deferred=len(deferred),
            urgent_reasons=urgent_reasons,
            mention=s.urgent_mention if urgent_reasons else "none",
            candidates=candidates,
        )

        # Only articles that actually went out are recorded and removed from
        # the queue. A failed send stays a candidate for the next arbitration.
        for article, summary in posted:
            self.state.mark_published(
                article.url,
                article.title,
                article.source,
                summary.severity,
                cves=article.cves,
                kev_cves=article.kev_cves,
            )
        self.queue.remove([state_mod.url_hash(a.url) for a, _ in posted])

        report["posted"] = report.get("posted", 0) + len(posted)
        if s.ai_provider != "none":
            report["degraded"] += sum(1 for _, x in posted if x.generated_by == "heuristic")
        return len(posted)

    async def _escalate_kev(self, channel, report: dict) -> None:
        """
        Path 0: KEV retrospective escalation.

        A CVE can enter the KEV catalog days or weeks after its article was
        already published as a routine Medium/High.
        """
        s = self.settings
        tracked = self.state.tracked_cves()
        if not tracked:
            return

        # collect() skips enrichment on a quiet cycle, and a one-shot run
        # starts with an empty catalog: without this the check would find
        # nothing, without any error.
        await self.enricher.ensure_kev()

        newly_kev = self.enricher.in_kev(tracked)
        pending = self.state.pending_kev_escalations(newly_kev)
        slots = self.budget.kev_escalation_slots_left(s.kev_retro_max_per_day)
        if not pending or slots <= 0:
            return

        batch = pending[:slots]
        ransomware_cves = {
            e["cve"] for e in batch if self.enricher.kev_ransomware([e["cve"]])
        }
        sent = await publisher.publish_kev_escalations(
            channel, batch, ransomware_cves=ransomware_cves, mention=s.urgent_mention,
        )
        for cve in sent:
            self.state.record_kev_escalation(cve)
        self.budget.note_kev_escalation(len(sent))
        report["kev_escalations"] = len(sent)
        if sent:
            log.warning("KEV retrospective escalation: %s", ", ".join(sent))

    async def _publish_urgent(self, channel, report: dict) -> None:
        """Path 1: urgent alerts, published immediately and outside the quota."""
        s = self.settings
        slots = self.budget.urgent_slots_left(s.urgent_daily_max)
        urgent, reasons = [], {}
        if slots > 0:
            ranked = [article for _, article in self.queue.ranked()]
            for article in selection_mod.distinct_stories(ranked, self.state.tracked_cves()):
                flagged, reason = selection_mod.is_urgent(article, s)
                if flagged:
                    urgent.append(article)
                    reasons[state_mod.url_hash(article.url)] = reason
                if len(urgent) >= slots:
                    break
        if urgent:
            log.warning("Urgent publication of %d article(s)", len(urgent))
            sent = await self.publish_selection(channel, urgent, report, reasons)
            self.budget.note_urgent(sent)
            report["urgent"] = sent

    async def _publish_digest(self, channel, report: dict) -> None:
        """Path 2: daily digest."""
        s = self.settings
        # Relative selection: the top N of the day, not whatever clears a
        # fixed bar (impossible to calibrate).
        ranked = selection_mod.distinct_stories(
            [article for _, article in self.queue.ranked()],
            self.state.tracked_cves(),
        )

        # Low floor: it only screens out obviously off-topic articles.
        relevant = [a for a in ranked if a.score >= s.digest_floor_score]
        chosen = relevant[: s.daily_quota]

        # Anti-silence: a quiet day means a short watch, not no watch. The
        # cap always wins (min() against an inconsistent setting).
        target = min(s.digest_min_articles, s.daily_quota)
        if len(chosen) < target and ranked:
            remainder = [a for a in ranked if a not in chosen]
            missing = target - len(chosen)
            chosen += remainder[:missing]
            if remainder[:missing]:
                log.info(
                    "Quiet day: %d article(s) added below the floor to keep up the pace",
                    len(remainder[:missing]),
                )

        if not chosen:
            # The only remaining possible case of silence: an empty queue.
            log.info("Daily digest: queue is empty, nothing to publish.")
            self.budget.note_digest()
            return

        log.info(
            "Daily digest: %d article(s) selected out of %d queued (scores: %s)",
            len(chosen), len(self.queue), [a.score for a in chosen],
        )
        report["digest"] = await self.publish_selection(
            channel, chosen, report, candidates=len(ranked),
            # Runs can be hours apart: holding the digest back for the AI can
            # lose it for the day, and a plainer digest beats none.
            degrade=True if s.digest_degrade_on_quota else None,
        )
        # Nothing went out (AI quota, Discord error): the digest stays due
        # and the next cycle tries again.
        if report["digest"]:
            self.budget.note_digest()

    async def run_cycle(self, channel: discord.abc.Messageable, force_digest: bool = False) -> dict:
        """
        A full cycle.

        Always collects; only publishes in two cases: a confirmed urgent alert,
        or daily digest time. This split is what makes it possible to hold to
        2-4 articles a day while still watching feeds every hour.
        """
        s = self.settings
        async with self.cycle_lock:
            self.state.note_cycle_started()
            report = {
                "fetched": 0, "queued": 0, "queue_size": 0,
                "urgent": 0, "digest": 0, "posted": 0, "deferred": 0, "degraded": 0,
                "kev_escalations": 0, "error": None,
            }
            try:
                # Learned weights refreshed BEFORE collection: scoring new
                # articles must reflect the most recent votes.
                await self.refresh_feedback(channel)

                await self.collect(report)

                if s.enable_kev_retro_check:
                    await self._escalate_kev(channel, report)
                if s.enable_urgent:
                    await self._publish_urgent(channel, report)
                if force_digest or self.budget.digest_due():
                    await self._publish_digest(channel, report)

                report["queue_size"] = len(self.queue)
                self.state.log_run(**report)
                return report

            except Exception as exc:
                log.exception("Cycle failed")
                report["error"] = f"{type(exc).__name__}: {exc}"
                self.state.log_run(**report)
                return report
