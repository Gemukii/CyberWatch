#!/usr/bin/env python3
"""
Entry point: scheduling, slash commands, watch cycle.

A cycle always collects, but only publishes on a confirmed urgent alert or
at digest time. Pipeline details: docs/ARCHITECTURE.md
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time

import discord
from discord import app_commands
from discord.ext import commands, tasks

import feedback as feedback_mod
import filters
import publisher
import selection
import sources
import state as state_mod
from config import settings
from enrichment import Enricher
from selection import CandidateQueue, DailyBudget
from state import State
from summarizer import Summarizer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)-12s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("cyberwatch")
logging.getLogger("discord").setLevel(logging.WARNING)

# Slash commands only: avoids the privileged MESSAGE CONTENT intent.
intents = discord.Intents.default()

bot = commands.Bot(command_prefix="!cyberwatch-unused", intents=intents, help_command=None)

state = State(retention_days=settings.retention_days)
summarizer = Summarizer(settings)
enricher = Enricher(settings)

# Prevents two simultaneous cycles (auto loop + manual command).
queue = CandidateQueue(ttl_hours=settings.candidate_ttl_hours)

# Weights learned from 👍/👎 reactions. Recomputed periodically from
# Discord history, never stored: see feedback.py.
learned = feedback_mod.LearnedWeights(
    min_votes=settings.feedback_min_votes,
    max_adjustment=settings.feedback_max_adjustment,
)
_feedback_refreshed_at = 0.0


async def refresh_feedback(channel, force: bool = False) -> bool:
    """
    Recomputes learned weights if the cache has expired.

    Re-reading history costs Discord API calls: this only runs once per
    `FEEDBACK_TTL_HOURS`, not every cycle.
    """
    global learned, _feedback_refreshed_at
    if not settings.enable_feedback or channel is None:
        return False
    if not force and (time.time() - _feedback_refreshed_at) < settings.feedback_ttl_hours * 3600:
        return False
    learned = await feedback_mod.collect_feedback(
        channel,
        lookback_days=settings.feedback_lookback_days,
        min_votes=settings.feedback_min_votes,
        max_adjustment=settings.feedback_max_adjustment,
        message_limit=settings.feedback_message_limit,
    )
    _feedback_refreshed_at = time.time()
    return True
budget = DailyBudget(
    timezone_name=settings.timezone_name,
    digest_hour=settings.digest_hour,
)

cycle_lock = asyncio.Lock()


# --- Watch cycle ---
async def collect(report: dict) -> list:
    """
    Free step: collects, filters, enriches, and feeds the candidate queue.
    No AI call happens here, so it can run every hour at no cost.
    """
    articles, feed_results = await sources.fetch_all_feeds(
        settings.feeds, settings.max_age_hours
    )
    state.record_feed_results(feed_results)
    report["fetched"] = len(articles)

    unhealthy = state.unhealthy_feeds(settings.feed_failure_threshold)
    if unhealthy:
        log.warning("Feeds down: %s", ", ".join(f.name for f in unhealthy))

    if not articles:
        return []

    # Pre-filter on title + RSS summary, lowered threshold: keeps margin
    # before the network-costly steps.
    shortlist = filters.select_articles(
        articles,
        state,
        min_score=max(1, settings.min_score - 3),
        similarity=settings.dedup_similarity,
        limit=settings.shortlist_limit,
    )
    if not shortlist:
        return []

    if settings.fetch_fulltext:
        await sources.enrich_with_fulltext(
            shortlist, settings.user_agent, settings.http_timeout, settings.fulltext_max_chars
        )

    # KEV / EPSS enrichment, then re-scoring on the full data.
    await enricher.enrich(shortlist)
    for article in shortlist:
        article.score, article.reasons = filters.score_article(
            article, feedback=learned if settings.enable_feedback else None
        )

    retained = [a for a in shortlist if a.score >= settings.min_score]

    # A candidate already in the queue has its score refreshed: a CVE can
    # enter KEV between two cycles.
    added = 0
    for article in retained:
        if queue.add(article, state_mod.url_hash(article.url)):
            added += 1
    queue.purge(settings.candidate_ttl_hours)

    report["queued"] = added
    report["queue_size"] = len(queue)
    log.info(
        "Collection: %d articles -> %d queued (%d new, queue = %d)",
        len(articles), len(retained), added, len(queue),
    )
    return retained


async def publish_selection(
    channel: discord.abc.Messageable,
    selection: list,
    report: dict,
    urgent_reasons: dict[str, str] | None = None,
    candidates: int | None = None,
) -> int:
    """
    Summarizes then publishes an already-arbitrated selection, and removes
    the actually-published articles from the queue.
    """
    if not selection:
        return 0

    log.info("Summarizing %d article(s) via %s...", len(selection), settings.ai_provider)
    summarized, deferred = await summarizer.summarize_many(selection)
    report["deferred"] = report.get("deferred", 0) + len(deferred)

    posted = await publisher.publish(
        channel,
        summarized,
        settings.ai_provider,
        deferred=len(deferred),
        urgent_reasons=urgent_reasons,
        mention=settings.urgent_mention if urgent_reasons else "none",
        quota=None if urgent_reasons else settings.daily_quota,
        candidates=candidates,
    )

    # Only articles that actually went out are recorded and removed from
    # the queue. A failed send stays a candidate for the next arbitration.
    for article, summary in posted:
        state.mark_published(article.url, article.title, article.source, summary.severity)
    queue.remove([state_mod.url_hash(a.url) for a, _ in posted])

    report["posted"] = report.get("posted", 0) + len(posted)
    return len(posted)


async def run_cycle(channel: discord.abc.Messageable, force_digest: bool = False) -> dict:
    """
    A full cycle.

    Always collects; only publishes in two cases: a confirmed urgent alert,
    or daily digest time. This split is what makes it possible to hold to
    2-4 articles a day while still watching feeds every hour.
    """
    async with cycle_lock:
        report = {
            "fetched": 0, "queued": 0, "queue_size": 0,
            "urgent": 0, "digest": 0, "posted": 0, "deferred": 0, "error": None,
        }
        try:
            # Learned weights refreshed BEFORE collection: scoring new
            # articles must reflect the most recent votes.
            await refresh_feedback(channel)

            await collect(report)

            # --- Path 1: urgent alerts, published immediately and outside the quota ---
            if settings.enable_urgent:
                slots = budget.urgent_slots_left(settings.urgent_daily_max)
                urgent, reasons = [], {}
                if slots > 0:
                    for key, article in queue.ranked():
                        flagged, reason = selection.is_urgent(article, settings)
                        if flagged:
                            urgent.append(article)
                            reasons[key] = reason
                        if len(urgent) >= slots:
                            break
                if urgent:
                    log.warning("Urgent publication of %d article(s)", len(urgent))
                    sent = await publish_selection(channel, urgent, report, reasons)
                    budget.note_urgent(sent)
                    report["urgent"] = sent

            # --- Path 2: daily digest ---
            if force_digest or budget.digest_due():
                # Relative selection: the top N of the day, not whatever
                # clears a fixed bar (impossible to calibrate).
                ranked = [article for _, article in queue.ranked()]

                # Low floor: it only screens out obviously off-topic articles.
                relevant = [
                    a for a in ranked if a.score >= settings.digest_floor_score
                ]
                chosen = relevant[: settings.daily_quota]

                # Anti-silence: a quiet day means a short watch, not no
                # watch. The cap always wins (min() against an inconsistent setting).
                target = min(settings.digest_min_articles, settings.daily_quota)
                if len(chosen) < target and ranked:
                    remainder = [a for a in ranked if a not in chosen]
                    missing = target - len(chosen)
                    chosen += remainder[:missing]
                    if remainder[:missing]:
                        log.info(
                            "Quiet day: %d article(s) added below the floor "
                            "to keep up the pace",
                            len(remainder[:missing]),
                        )

                if chosen:
                    log.info(
                        "Daily digest: %d article(s) selected out of %d queued "
                        "(scores: %s)",
                        len(chosen), len(queue), [a.score for a in chosen],
                    )
                    report["digest"] = await publish_selection(
                        channel, chosen, report, candidates=len(ranked)
                    )
                else:
                    # The only remaining possible case of silence: an empty queue.
                    log.info("Daily digest: queue is empty, nothing to publish.")
                budget.note_digest()

            report["queue_size"] = len(queue)
            state.log_run(**report)
            return report

        except Exception as exc:
            log.exception("Cycle failed")
            report["error"] = f"{type(exc).__name__}: {exc}"
            state.log_run(**report)
            return report


async def resolve_channel():
    """Fetches the publishing channel (local cache, else an API call)."""
    channel = bot.get_channel(settings.channel_id)
    if channel is not None:
        return channel
    try:
        return await bot.fetch_channel(settings.channel_id)
    except discord.DiscordException as exc:
        log.error("Channel %s unreachable: %s", settings.channel_id, exc)
        return None


@tasks.loop(minutes=settings.interval_minutes)
async def scheduled_watch():
    """Automatic loop. The first run starts right after connecting."""
    channel = await resolve_channel()
    if channel is None:
        return
    await run_cycle(channel)


@scheduled_watch.before_loop
async def before_watch():
    await bot.wait_until_ready()


# --- Lifecycle ---
@bot.event
async def setup_hook():
    """Slash command sync, run before connecting to the gateway."""
    if settings.guild_id:
        guild = discord.Object(id=settings.guild_id)
        bot.tree.copy_global_to(guild=guild)
        await bot.tree.sync(guild=guild)
        log.info("Slash commands synced to guild %s", settings.guild_id)
    else:
        await bot.tree.sync()
        log.info("Slash commands synced globally (propagation: up to 1h)")


@bot.event
async def on_ready():
    log.info("Logged in as %s (id=%s)", bot.user, bot.user.id)

    # on_ready fires again on every reconnect. Everything below must
    # therefore be idempotent — State.prime_from_channel is, and so is the loop.
    if not state.primed:
        log.info(
            "Config: %d feeds · %d min · AI=%s · daily quota %d · retention %dd",
            len(settings.feeds), settings.interval_minutes, settings.ai_provider,
            settings.daily_quota, settings.retention_days,
        )
        channel = await resolve_channel()
        if channel is not None:
            await state.prime_from_channel(
                channel, limit=settings.history_limit, budget=budget
            )
        else:
            log.warning(
                "Channel %s not found: index starts empty, recent articles "
                "may be republished once.",
                settings.channel_id,
            )

    if not scheduled_watch.is_running():
        scheduled_watch.start()


# --- Slash commands ---
@bot.tree.command(
    name="cyber-now",
    description="Collect immediately, and publish today's digest if it hasn't gone out yet",
)
@app_commands.checks.cooldown(1, 120.0)
async def cyber_now(interaction: discord.Interaction):
    if cycle_lock.locked():
        await interaction.response.send_message("⏳ A cycle is already running.", ephemeral=True)
        return

    # A cycle far exceeds the 3s allowed to respond.
    await interaction.response.defer(thinking=True)
    report = await run_cycle(interaction.channel)

    if report["error"]:
        message = f"❌ Error: `{report['error'][:300]}`"
    elif report["posted"]:
        parts = []
        if report["urgent"]:
            parts.append(f"🚨 {report['urgent']} urgent alert(s)")
        if report["digest"]:
            parts.append(f"📰 {report['digest']} article(s) in the digest")
        message = "✅ " + " · ".join(parts)
        if report["deferred"]:
            message += f" · ⏸️ {report['deferred']} deferred, AI quota"
    else:
        message = (
            f"✅ Collection done: {report['fetched']} articles analyzed, "
            f"{report['queue_size']} queued. "
        )
        if budget.last_digest_date == budget.today_key():
            message += "Today's digest has already gone out."
        else:
            message += f"Digest expected <t:{int(budget.next_digest_at().timestamp())}:R>."
    await interaction.followup.send(message)


@bot.tree.command(
    name="cyber-digest",
    description="Force the digest to be sent now, without waiting for its scheduled time",
)
@app_commands.checks.cooldown(1, 300.0)
async def cyber_digest(interaction: discord.Interaction):
    """
    Useful for testing the output, or catching up after downtime. Doesn't
    bypass the quality floor: if nothing clears DIGEST_FLOOR_SCORE, nothing
    is published.
    """
    if cycle_lock.locked():
        await interaction.response.send_message("⏳ A cycle is already running.", ephemeral=True)
        return
    await interaction.response.defer(thinking=True)
    report = await run_cycle(interaction.channel, force_digest=True)

    if report["error"]:
        await interaction.followup.send(f"❌ Error: `{report['error'][:300]}`")
    elif report["digest"]:
        await interaction.followup.send(f"✅ Digest sent: {report['digest']} article(s).")
    else:
        await interaction.followup.send(
            "Queue is empty: nothing has been collected since the last digest yet. "
            "The next collection cycle will fill it."
        )


@bot.tree.command(
    name="cyber-queue",
    description="Shows the candidates in the running for the next digest",
)
async def cyber_queue(interaction: discord.Interaction):
    """Makes the arbitration transparent: what would pass, what would be dropped."""
    ranked = queue.ranked()
    if not ranked:
        await interaction.response.send_message(
            "Queue is empty. The next collection cycle will fill it.", ephemeral=True
        )
        return

    lines = []
    for rank, (_, article) in enumerate(ranked[:12], start=1):
        # Selection is relative: rank decides, not the absolute score.
        if rank <= settings.daily_quota and article.score >= settings.digest_floor_score:
            marker = "✅"
        elif rank <= settings.digest_min_articles:
            marker = "🟨"  # rescued by the anti-silence guarantee
        elif article.score >= settings.digest_floor_score:
            marker = "🔸"  # relevant, but outside the quota
        else:
            marker = "▫️"  # below the relevance floor
        kev = " · KEV" if getattr(article, "kev_cves", None) else ""
        lines.append(f"{marker} `{article.score:>3}` {article.title[:70]}{kev}")

    embed = discord.Embed(
        title=f"🗳️ Queue — {len(ranked)} candidate(s)",
        description="\n".join(lines),
        color=0x5865F2,
    )
    embed.set_footer(
        text=(
            f"✅ would make the digest (top {settings.daily_quota}) · 🟨 rescued "
            f"by anti-silence · 🔸 relevant but outside quota · ▫️ below the floor "
            f"({settings.digest_floor_score})"
        )
    )
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(
    name="cyber-feedback",
    description="What the bot has learned from your 👍 / 👎 votes",
)
async def cyber_feedback(interaction: discord.Interaction):
    """
    Transparency for the learning loop.

    Learned weighting you can't inspect is impossible to debug and
    impossible to trust: this command shows exactly which signals were
    adjusted, and on how many votes.
    """
    if not settings.enable_feedback:
        await interaction.response.send_message(
            "The feedback loop is disabled (`ENABLE_FEEDBACK=false`).",
            ephemeral=True,
        )
        return

    await interaction.response.defer(ephemeral=True, thinking=True)
    await refresh_feedback(interaction.channel, force=True)

    embed = discord.Embed(
        title="🎓 Weights learned from your votes",
        color=0x5865F2,
        description=(
            f"**{learned.votes_seen}** vote(s) across **{learned.articles_voted}** "
            f"article(s), {settings.feedback_lookback_days}-day window."
        ),
    )

    if not learned.is_active:
        embed.add_field(
            name="No active adjustment",
            value=(
                f"At least **{settings.feedback_min_votes} votes** on the same "
                "signal are needed before it gets adjusted. React with 👍 or 👎 "
                "on published articles — the bot pre-posts both reactions for you."
            ),
            inline=False,
        )
        await interaction.followup.send(embed=embed, ephemeral=True)
        return

    top_signals = learned.top_signals(8)
    if top_signals:
        lines = [
            f"`{delta:+d}` **{name}** — {t.up}👍 / {t.down}👎"
            for name, t, delta in top_signals
        ]
        embed.add_field(name="Signals", value="\n".join(lines), inline=False)

    top_sources = learned.top_sources(5)
    if top_sources:
        lines = [
            f"`{delta:+d}` **{name}** — {t.up}👍 / {t.down}👎"
            for name, t, delta in top_sources
        ]
        embed.add_field(name="Sources", value="\n".join(lines), inline=False)

    embed.set_footer(
        text=(
            f"Adjustment capped at ±{settings.feedback_max_adjustment} per signal. "
            "Factual signals (KEV, EPSS, CVE, CVSS) are never adjusted."
        )
    )
    await interaction.followup.send(embed=embed, ephemeral=True)


@bot.tree.command(name="cyber-status", description="Bot status and last cycle")
async def cyber_status(interaction: discord.Interaction):
    embed = discord.Embed(title="📊 Watch status", color=0x5865F2)
    embed.add_field(name="Active feeds", value=str(len(settings.feeds)), inline=True)
    embed.add_field(name="Collection", value=f"every {settings.interval_minutes} min", inline=True)
    embed.add_field(name="AI engine", value=settings.ai_provider, inline=True)

    # The daily budget is the single most useful piece of info day to day.
    digest_done = budget.last_digest_date == budget.today_key()
    embed.add_field(
        name="Today's budget",
        value=(
            f"{settings.daily_quota} max at {settings.digest_hour:02d}:00 · "
            + ("already sent" if digest_done else f"<t:{int(budget.next_digest_at().timestamp())}:R>")
        ),
        inline=True,
    )
    embed.add_field(
        name="Queue",
        value=(
            f"{len(queue)} candidate(s)"
            + (f" · top {queue.top_scores(3)}" if len(queue) else "")
        ),
        inline=True,
    )
    embed.add_field(
        name="Urgent alerts today",
        value=f"{budget.urgent_count_today()} / {settings.urgent_daily_max}",
        inline=True,
    )
    embed.add_field(name="CISA KEV", value=enricher.status(), inline=True)
    embed.add_field(
        name=f"Published ({settings.retention_days}d)",
        value=str(state.count_published(settings.retention_days)),
        inline=True,
    )
    embed.add_field(
        name="Index",
        value=f"in-memory · {state.memory_footprint()}"
        + ("" if state.primed else " · ⚠️ not primed"),
        inline=True,
    )
    embed.add_field(name="Uptime", value=state.uptime(), inline=True)

    unhealthy = state.unhealthy_feeds(settings.feed_failure_threshold)
    if unhealthy:
        embed.add_field(
            name="🔴 Feeds down",
            value="\n".join(f"• {f.name} ({f.consecutive_failures} cycles)" for f in unhealthy)[:1024],
            inline=False,
        )

    last = state.last_run()
    if last:
        value = (
            f"<t:{last['started_at']}:R>\n"
            f"{last['fetched']} collected · {last.get('queued', 0)} queued · "
            f"{last['posted']} published"
        )
        if last.get("deferred"):
            value += f" · {last['deferred']} deferred"
        if last.get("error"):
            value += f"\n⚠️ `{last['error'][:150]}`"
        embed.add_field(name="Last cycle", value=value, inline=False)
    else:
        embed.add_field(name="Last cycle", value="none yet", inline=False)

    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="cyber-sources", description="Watched feeds and their health")
async def cyber_sources(interaction: discord.Interaction):
    lines = state.feed_report(settings.feed_failure_threshold)
    if not lines:
        lines = [f"• **{f['name']}** (weight {f['weight']}) — not queried yet"
                 for f in settings.feeds]
    await interaction.response.send_message(
        embed=discord.Embed(
            title="📡 Watched feeds",
            description="\n".join(lines)[:4000],
            color=0x5865F2,
        )
    )


@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    if isinstance(error, app_commands.CommandOnCooldown):
        message = f"⏳ Too fast — try again in {error.retry_after:.0f}s."
    else:
        log.error("Command error: %s", error)
        message = f"❌ `{str(error)[:300]}`"
    if interaction.response.is_done():
        await interaction.followup.send(message, ephemeral=True)
    else:
        await interaction.response.send_message(message, ephemeral=True)


# --------------------------------------------------------------------------- #
def main() -> None:
    problems = settings.validate()
    if problems:
        print("Invalid configuration:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print("\nCheck your .env file (see .env.example).", file=sys.stderr)
        sys.exit(1)

    for warning in settings.warnings():
        log.warning(warning)

    bot.run(settings.discord_token, log_handler=None)


if __name__ == "__main__":
    main()