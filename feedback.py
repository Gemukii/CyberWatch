"""
Learning scoring weights from 👍/👎 reactions.

Votes live in Discord, so weights are recomputed from history rather than
stored. Guardrails and math: docs/ARCHITECTURE.md §4.
"""

from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

log = logging.getLogger(__name__)

# Reactions recognized as a vote. Any other reaction is ignored
UPVOTE = "👍"
DOWNVOTE = "👎"

# Marker written into the embed footer. Format: "sig:name1,name2,name3"
SIGNAL_PREFIX = "sig:"
SIGNAL_RE = re.compile(r"sig:([a-z0-9\-,]+)", re.IGNORECASE)

# These signals describe facts, not taste: they're never learned from.
FACTUAL_SIGNALS = frozenset({"kev", "epss", "cve", "cvss"})


def encode_signals(signals: list[str]) -> str:
    """Serializes signals into the embed footer."""
    learnable = [s for s in signals if s not in FACTUAL_SIGNALS]
    return SIGNAL_PREFIX + ",".join(learnable[:8]) if learnable else ""


def decode_signals(footer_text: str) -> list[str]:
    """Reads signals back from an already-published embed's footer."""
    match = SIGNAL_RE.search(footer_text or "")
    if not match:
        return []
    return [s for s in match.group(1).lower().split(",") if s]


@dataclass
class Tally:
    """Vote counter for a signal or a source."""
    up: int = 0
    down: int = 0

    @property
    def total(self) -> int:
        return self.up + self.down

    @property
    def ratio(self) -> float:
        """Between -1 (unanimous rejection) and +1 (unanimous approval)."""
        return (self.up - self.down) / self.total if self.total else 0.0


@dataclass
class LearnedWeights:
    """
    Learned adjustments, ready to be applied to scoring.

    Built by `collect_feedback()`, then passed to `filters.score_article()`.
    """
    signals: dict[str, Tally] = field(default_factory=dict)
    sources: dict[str, Tally] = field(default_factory=dict)
    votes_seen: int = 0
    articles_voted: int = 0
    computed_at: float = field(default_factory=time.time)
    min_votes: int = 3
    max_adjustment: int = 4

    def _delta(self, tally: Tally) -> int:
        """
        Converts a vote count into a score adjustment.

        Confidence grows with the number of votes: 3 unanimous votes carry
        less weight than 20. The n/(n+3) factor keeps a small sample from
        producing the maximum adjustment.
        """
        if tally.total < self.min_votes:
            return 0
        confidence = tally.total / (tally.total + 3)
        return round(self.max_adjustment * tally.ratio * confidence)

    def adjustment(self, signals: list[str], source: str = "") -> tuple[int, str]:
        """
        Total adjustment for an article, with a human-readable explanation.

        Returns (delta, explanation). The explanation feeds `/cyber-queue`
        and the logs: an opaque feedback loop is impossible to debug.
        """
        details: list[str] = []
        total = 0

        for name in signals:
            if name in FACTUAL_SIGNALS:
                continue  # guardrail #1
            tally = self.signals.get(name)
            if not tally:
                continue
            delta = self._delta(tally)
            if delta:
                total += delta
                details.append(f"{name} {delta:+d}")

        if source:
            tally = self.sources.get(source)
            if tally:
                delta = self._delta(tally)
                if delta:
                    total += delta
                    details.append(f"{source} {delta:+d}")

        # Guardrail #3: global cap, so a pile-up of small adjustments never
        # ends up dominating the factual score.
        cap = self.max_adjustment * 2
        total = max(-cap, min(cap, total))
        return total, ", ".join(details[:4]) if details else "—"

    def top_signals(self, count: int = 8) -> list[tuple[str, Tally, int]]:
        """Most influential signals, for the transparency command."""
        rows = [
            (name, tally, self._delta(tally))
            for name, tally in self.signals.items()
            if tally.total >= self.min_votes
        ]
        rows.sort(key=lambda row: abs(row[2]), reverse=True)
        return rows[:count]

    def top_sources(self, count: int = 5) -> list[tuple[str, Tally, int]]:
        rows = [
            (name, tally, self._delta(tally))
            for name, tally in self.sources.items()
            if tally.total >= self.min_votes
        ]
        rows.sort(key=lambda row: abs(row[2]), reverse=True)
        return rows[:count]

    @property
    def is_active(self) -> bool:
        """True as soon as at least one non-zero adjustment applies."""
        return any(self._delta(t) for t in self.signals.values()) or any(
            self._delta(t) for t in self.sources.values()
        )


def _source_from_author(author_name: str) -> str:
    """The embed's author field holds "Source · Original title"."""
    return (author_name or "").split("·")[0].strip()


async def collect_feedback(
    channel,
    lookback_days: int = 30,
    min_votes: int = 3,
    max_adjustment: int = 4,
    message_limit: int = 500,
) -> LearnedWeights:
    """
    Re-reads the channel's history and aggregates reactions into learned weights.

    Never raises: unavailable feedback should degrade the ranking, not
    interrupt the watch.
    """
    weights = LearnedWeights(min_votes=min_votes, max_adjustment=max_adjustment)
    signals: dict[str, Tally] = defaultdict(Tally)
    sources: dict[str, Tally] = defaultdict(Tally)

    after = datetime.now(tz=timezone.utc) - timedelta(days=lookback_days)
    try:
        async for message in channel.history(limit=message_limit or None, after=after):
            if not message.reactions:
                continue
            for embed in message.embeds:
                if not embed.url:
                    continue  # digest header, status message...: not an article

                footer = embed.footer.text if embed.footer else ""
                names = decode_signals(footer)
                source = _source_from_author(embed.author.name if embed.author else "")
                if not names and not source:
                    continue

                up = down = 0
                for reaction in message.reactions:
                    emoji = str(reaction.emoji)
                    # Subtract the bot's own reaction: it pre-posts both
                    # emojis so voting is a single tap.
                    count = max(0, reaction.count - (1 if reaction.me else 0))
                    if emoji == UPVOTE:
                        up += count
                    elif emoji == DOWNVOTE:
                        down += count

                if not (up or down):
                    continue

                weights.votes_seen += up + down
                weights.articles_voted += 1
                for name in names:
                    signals[name].up += up
                    signals[name].down += down
                if source:
                    sources[source].up += up
                    sources[source].down += down

    except Exception as exc:
        log.warning("Could not collect feedback (%s) — scoring left unadjusted", exc)
        return weights

    weights.signals = dict(signals)
    weights.sources = dict(sources)
    if weights.articles_voted:
        log.info(
            "Feedback: %d vote(s) across %d article(s), %d signal(s) adjusted",
            weights.votes_seen,
            weights.articles_voted,
            sum(1 for t in weights.signals.values() if weights._delta(t)),
        )
    return weights