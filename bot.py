#!/usr/bin/env python3
"""
Resident Discord bot: scheduling and slash commands.

Needs a process that stays online. The cycle itself lives in pipeline.py;
run_once.py runs it without a resident process, minus the slash commands.
"""

from __future__ import annotations

import logging
import sys

import discord
from discord import app_commands
from discord.ext import commands, tasks

from config import settings
from pipeline import Pipeline

from cve_service import (
    CVEAPIError,
    CVENotFoundError,
    CVEService,
    InvalidCVEIDError,
)

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

pipeline = Pipeline(settings)
state = pipeline.state
queue = pipeline.queue
budget = pipeline.budget
enricher = pipeline.enricher
cycle_lock = pipeline.cycle_lock
cve_service = CVEService(settings)


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
    state.note_cycle_started()
    channel = await resolve_channel()
    if channel is None:
        state.log_run(error="Discord channel unavailable")
        return
    await pipeline.run_cycle(channel)


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
    report = await pipeline.run_cycle(interaction.channel)

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
    report = await pipeline.run_cycle(interaction.channel, force_digest=True)

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
    name="cyber-cve",
    description="Get detailed information about a CVE",
)
@app_commands.describe(cve_id="CVE identifier, e.g. CVE-2024-3094")
@app_commands.checks.cooldown(1, 10.0)
async def cyber_cve(
    interaction: discord.Interaction,
    cve_id: str,
):
    """Display detailed information about a CVE."""

    await interaction.response.defer(thinking=True, ephemeral=True)

    try:
        cve = await cve_service.get(cve_id)

    except InvalidCVEIDError:
        await interaction.followup.send(
            f"❌ Invalid CVE identifier: `{cve_id}`",
            ephemeral=True,
        )
        return

    except CVENotFoundError:
        await interaction.followup.send(
            f"❌ CVE `{cve_id.upper()}` was not found.",
            ephemeral=True,
        )
        return

    except CVEAPIError:
        log.exception("Failed to retrieve CVE %s", cve_id)
        await interaction.followup.send(
            "❌ Unable to retrieve information from the NVD API. "
            "Please try again later.",
            ephemeral=True,
        )
        return

    embed = discord.Embed(
        title=f"🛡️ {cve.cve_id}",
        description=cve.description[:4096],
        color=0x5865F2,
    )

    if cve.cvss_score is not None:
        cvss = f"**{cve.cvss_score:.1f}**"

        if cve.cvss_severity:
            cvss += f" · {cve.cvss_severity}"

        if cve.cvss_version:
            cvss += f" (CVSS {cve.cvss_version})"

        embed.add_field(
            name="CVSS",
            value=cvss,
            inline=True,
        )
    else:
        embed.add_field(
            name="CVSS",
            value="Not available",
            inline=True,
        )

    if cve.published:
        embed.add_field(
            name="Published",
            value=cve.published[:10],
            inline=True,
        )

    if cve.last_modified:
        embed.add_field(
            name="Last modified",
            value=cve.last_modified[:10],
            inline=True,
        )

    if cve.references:
        references = "\n".join(
            f"• {url}" for url in cve.references[:8]
        )

        embed.add_field(
            name=f"References ({len(cve.references)})",
            value=references[:1024],
            inline=False,
        )

    embed.set_footer(text="Source: NVD")

    await interaction.followup.send(
        embed=embed,
        ephemeral=True,
    )

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
    await pipeline.refresh_feedback(interaction.channel, force=True)
    learned = pipeline.learned

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
    health = state.cycle_health()
    if health["consecutive_failures"]:
        status_label, status_color = "🔴 degraded", 0xE01E37
    elif health["finished_at"] is None:
        status_label, status_color = "🟡 starting", 0xF2C14E
    else:
        status_label, status_color = "🟢 operational", 0x4C9F70

    embed = discord.Embed(title="📊 Watch status", color=status_color)
    embed.add_field(name="Runtime", value=status_label, inline=True)
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
    if settings.enable_kev_retro_check:
        embed.add_field(
            name="KEV retro-watch",
            value=(
                f"{len(state.tracked_cves())} CVE(s) tracked · "
                f"{budget.kev_escalation_count_today()}/{settings.kev_retro_max_per_day} "
                "escalated today"
            ),
            inline=True,
        )
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
        if last.get("kev_escalations"):
            value += f" · 🚨 {last['kev_escalations']} KEV escalation(s)"
        if last.get("error"):
            value += f"\n⚠️ `{last['error'][:150]}`"
        embed.add_field(name="Last cycle", value=value, inline=False)
    else:
        embed.add_field(name="Last cycle", value="none yet", inline=False)

    if health["started_at"]:
        cycle_value = f"started <t:{health['started_at']}:R>"
        if health["finished_at"]:
            cycle_value += f" · finished <t:{health['finished_at']}:R>"
        if health["consecutive_failures"]:
            cycle_value += f"\n{health['consecutive_failures']} consecutive failure(s)"
        if health["last_error"]:
            cycle_value += f"\n⚠️ `{health['last_error'][:150]}`"
        embed.add_field(name="Runtime heartbeat", value=cycle_value, inline=False)

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