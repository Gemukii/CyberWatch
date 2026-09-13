"""
Building and sending Discord embeds.

API limits: title 256, description 4096, field 1024, footer 2048,
total 6000, 10 embeds per message.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import discord

from sources import Article
from feedback import DOWNVOTE, UPVOTE, encode_signals
from summarizer import Summary

log = logging.getLogger(__name__)

# Color code by severity, readable in both dark and light theme.
SEVERITY_STYLE = {
    "Critical": (0xE01E37, "🔴"),
    "High":     (0xF07C00, "🟠"),
    "Medium":   (0xF2C14E, "🟡"),
    "Low":      (0x4C9F70, "🟢"),
}

# Markers written into header footers: they let state.py reconstruct, from
# Discord alone, what's already been published today.
DIGEST_MARKER = "#digest"
URGENT_MARKER = "#urgent"
KEV_ESCALATION_MARKER = "#kev-escalation"

TITLE_LIMIT = 256
AUTHOR_LIMIT = 256
FIELD_LIMIT = 1024
SAFE_DESC_LIMIT = 1800   # our own cap, well under Discord's

# No mention will ever be resolved by Discord from the bot's messages.
NO_MENTIONS = discord.AllowedMentions.none()


def _truncate(text: str, limit: int) -> str:
    """Cleanly truncates on a word boundary, with an ellipsis."""
    if len(text) <= limit:
        return text
    cut = text[: limit - 1]
    space = cut.rfind(" ")
    if space > limit * 0.6:
        cut = cut[:space]
    return cut.rstrip(" ,.;:") + "…"


def build_embed(
    article: Article, summary: Summary, urgent_reason: str | None = None
) -> discord.Embed:
    """Turns an (article, summary) pair into a ready-to-publish embed."""
    color, emoji = SEVERITY_STYLE.get(summary.severity, SEVERITY_STYLE["Medium"])

    lines = [f"• {_truncate(b, 260)}" for b in summary.bullets]
    description = _truncate("\n".join(lines), SAFE_DESC_LIMIT)

    embed = discord.Embed(
        title=_truncate(f"{emoji} {summary.title}", TITLE_LIMIT),
        url=article.url,
        description=description,
        color=color,
        timestamp=(
            datetime.fromtimestamp(article.published_ts, tz=timezone.utc)
            if article.published_ts
            else datetime.now(tz=timezone.utc)
        ),
    )

    # author.name = source + original title. Also used as the key to
    # rebuild the anti-duplicate index on startup (state.py).
    embed.set_author(name=_truncate(f"{article.source} · {article.title}", AUTHOR_LIMIT))

    embed.add_field(name="Severity", value=f"**{summary.severity}**", inline=True)

    # Authoritative signals: worth more than an adjective in an article.
    if article.kev_cves:
        embed.add_field(name="CISA KEV", value="⚠️ confirmed exploitation", inline=True)
    if article.epss_max is not None and article.epss_max >= 0.01:
        embed.add_field(name="EPSS 30d", value=f"{article.epss_max:.1%}", inline=True)

    if summary.cves:
        marked = [f"`{c}`" + ("⚠️" if c in article.kev_cves else "") for c in summary.cves]
        embed.add_field(name="CVE", value=_truncate(" · ".join(marked), FIELD_LIMIT), inline=False)

    # A detected injection attempt is flagged, never hidden: the reader
    # needs to know this summary deserves a second look.
    if summary.injection_flags:
        embed.add_field(
            name="⚠️ Suspicious content",
            value=_truncate(
                "Prompt-injection patterns detected in the source "
                f"({', '.join(summary.injection_flags)}). Summary should be double-checked.",
                FIELD_LIMIT,
            ),
            inline=False,
        )

    if urgent_reason:
        embed.add_field(
            name="🚨 Immediate alert",
            value=_truncate(urgent_reason, FIELD_LIMIT),
            inline=False,
        )

    # Signals recorded here: this is what makes a vote attributable to a
    # specific criterion rather than to the whole article.
    footer = f"Score {article.score}"
    encoded = encode_signals(getattr(article, "signals", []) or [])
    if encoded:
        footer += f" · {encoded}"
    if urgent_reason:
        footer += f" · {URGENT_MARKER}"
    if summary.tags:
        footer += " · " + " ".join(f"#{t}" for t in summary.tags)
    if summary.generated_by == "heuristic":
        footer += " · summary without AI"
    embed.set_footer(text=_truncate(footer, 300))

    return embed


def build_header_embed(
    count: int,
    provider: str,
    deferred: int = 0,
    urgent: bool = False,
    quota: int | None = None,
    candidates: int | None = None,
) -> discord.Embed:
    """
    Summary header.

    Two forms: the immediate alert, and the daily digest which reports how
    many candidates were dropped — that line is what makes the bot's
    selectivity visible to the reader.
    """
    if urgent:
        vuln_plural = "ies" if count > 1 else "y"
        return discord.Embed(
            title="🚨 Immediate cyber alert",
            description=(
                f"**{count}** vulnerabilit{vuln_plural} with confirmed or highly "
                "likely exploitation, published outside the daily digest."
            ),
            color=0xE01E37,
            timestamp=datetime.now(tz=timezone.utc),
        ).set_footer(text=f"Summaries: {provider} · {URGENT_MARKER}")

    description = f"**{count}** article{'s' if count != 1 else ''} selected today."
    if quota:
        description += f" Daily cap: {quota}."
    if candidates and candidates > count:
        description += f"\n{candidates - count} other candidate(s) dropped after arbitration."
    if deferred:
        description += f"\n⏸️ {deferred} deferred to the next cycle (AI quota)."

    return discord.Embed(
        title="🛡️ Cyber watch — today's digest",
        description=description,
        color=0x5865F2,
        timestamp=datetime.now(tz=timezone.utc),
    ).set_footer(text=f"Summaries: {provider} · {DIGEST_MARKER}")


def build_kev_escalation_embed(escalation: dict, ransomware: bool = False) -> discord.Embed:
    """
    A previously published article whose CVE has since entered the CISA
    KEV catalog: confirmed exploitation discovered after the fact.

    Links back to the original article rather than re-summarizing it — the
    escalation is the news here, not the vulnerability itself again.
    """
    cve = escalation["cve"]
    description = (
        f"**{cve}**, covered in an earlier watch entry, has since been "
        "added to the CISA KEV catalog: exploitation is now confirmed."
    )
    if ransomware:
        description += " It is tied to a known ransomware campaign."
    description += f"\n\n[Original article]({escalation['url']})"

    embed = discord.Embed(
        title=f"🚨 Escalation: {cve} now confirmed exploited",
        description=description,
        color=SEVERITY_STYLE["Critical"][0],
        timestamp=datetime.now(tz=timezone.utc),
    )
    if escalation.get("title"):
        embed.set_author(name=_truncate(escalation["title"], AUTHOR_LIMIT))
    # The CVE is embedded in the footer text itself so state.py can parse
    # it back out on priming, without needing a dedicated field.
    embed.set_footer(text=f"{cve} · {KEV_ESCALATION_MARKER}")
    return embed


async def publish_kev_escalations(
    channel: discord.abc.Messageable,
    escalations: list[dict],
    ransomware_cves: set[str] | None = None,
    mention: str = "none",
) -> list[str]:
    """
    Publishes one embed per newly-escalated CVE. Returns the CVEs actually
    sent — same principle as `publish()`: a failed send must not be marked
    as escalated, or the catalog entry is silently missed forever.
    """
    if not escalations:
        return []
    ransomware_cves = ransomware_cves or set()

    content, allowed = None, NO_MENTIONS
    if mention and mention.lower() != "none":
        if mention.lower() == "here":
            content, allowed = "@here", discord.AllowedMentions(everyone=True)
        elif mention.isdigit():
            content = f"<@&{mention}>"
            allowed = discord.AllowedMentions(roles=True)

    sent: list[str] = []
    for escalation in escalations:
        try:
            await channel.send(
                content=content,
                embed=build_kev_escalation_embed(
                    escalation, ransomware=escalation["cve"] in ransomware_cves
                ),
                allowed_mentions=allowed,
            )
            sent.append(escalation["cve"])
        except discord.HTTPException as exc:
            log.error("Failed to publish KEV escalation for %s: %s", escalation["cve"], exc)
    return sent


async def publish(
    channel: discord.abc.Messageable,
    items: list[tuple[Article, Summary]],
    provider: str,
    deferred: int = 0,
    urgent_reasons: dict[str, str] | None = None,
    mention: str = "none",
    quota: int | None = None,
    candidates: int | None = None,
    add_vote_reactions: bool = True,
) -> list[tuple[Article, Summary]]:
    """
    Sends the embeds and returns **only** the articles that were actually
    published.

    This matters: only those articles should be marked as seen. An embed
    whose send fails must remain a candidate for the next cycle, or it's
    lost for good.

    One message per article: easier to read in the channel, and lets
    people react or open a thread per article. discord.py handles rate
    limiting between sends on its own.
    """
    if not items:
        return []

    from state import url_hash  # local import: avoids a circular dependency

    urgent_reasons = urgent_reasons or {}
    is_urgent_batch = bool(urgent_reasons)
    posted: list[tuple[Article, Summary]] = []

    # A mention is only allowed for urgent alerts, and only when explicitly
    # configured. The daily digest never pings anyone.
    content, allowed = None, NO_MENTIONS
    if is_urgent_batch and mention and mention.lower() != "none":
        if mention.lower() == "here":
            content, allowed = "@here", discord.AllowedMentions(everyone=True)
        elif mention.isdigit():
            content = f"<@&{mention}>"
            allowed = discord.AllowedMentions(roles=True)

    try:
        await channel.send(
            content=content,
            embed=build_header_embed(
                len(items), provider, deferred,
                urgent=is_urgent_batch, quota=quota, candidates=candidates,
            ),
            allowed_mentions=allowed,
        )
    except discord.HTTPException as exc:
        log.warning("Header not published: %s", exc)

    for article, summary in items:
        try:
            reason = urgent_reasons.get(url_hash(article.url))
            message = await channel.send(
                embed=build_embed(article, summary, urgent_reason=reason),
                allowed_mentions=NO_MENTIONS,
            )
            posted.append((article, summary))
        except discord.HTTPException as exc:
            # Not marked as published: it will come back next cycle.
            log.error("Failed to publish %s: %s", article.url, exc)
            continue

        # Pre-posted reactions: voting is a single tap. A failure here
        # isn't serious, the article is already published.
        if add_vote_reactions:
            for emoji in (UPVOTE, DOWNVOTE):
                try:
                    await message.add_reaction(emoji)
                except discord.HTTPException as exc:
                    log.debug("Reaction %s not posted: %s", emoji, exc)
                    break  # missing permission: no point retrying
    return posted