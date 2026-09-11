"""
Tests for the feedback loop.

The cases covered focus mostly on **guardrails**: a system that learns
from a weak signal drifts fast, and that's what needs to be locked down
by tests rather than by vigilance.
"""

import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import feedback as fb


# --------------------------------------------------------------------------- #
# Signal encoding / decoding
# --------------------------------------------------------------------------- #
def test_encode_then_decode_preserves_signals():
    encoded = fb.encode_signals(["ransomware", "widespread-product"])
    assert fb.decode_signals(f"Score 21 · {encoded}") == ["ransomware", "widespread-product"]


def test_factual_signals_not_encoded():
    """KEV and EPSS aren't learned from: they must never be encoded."""
    encoded = fb.encode_signals(["kev", "epss", "ransomware"])
    assert fb.decode_signals(encoded) == ["ransomware"]


def test_footer_without_signals_returns_empty_list():
    assert fb.decode_signals("Score 12 · #fortinet") == []
    assert fb.decode_signals("") == []


def test_encoding_caps_the_number_of_signals():
    encoded = fb.encode_signals([f"signal-{i}" for i in range(20)])
    assert len(fb.decode_signals(encoded)) <= 8


# --------------------------------------------------------------------------- #
# Adjustment calculation
# --------------------------------------------------------------------------- #
def make_weights(signals=None, sources=None, min_votes=3, max_adjustment=4):
    return fb.LearnedWeights(
        signals={k: fb.Tally(*v) for k, v in (signals or {}).items()},
        sources={k: fb.Tally(*v) for k, v in (sources or {}).items()},
        min_votes=min_votes,
        max_adjustment=max_adjustment,
    )


def test_no_adjustment_below_the_minimum_votes():
    """One or two clicks must not steer the watch."""
    w = make_weights({"phishing": (2, 0)}, min_votes=3)
    delta, _ = w.adjustment(["phishing"])
    assert delta == 0


def test_positive_votes_increase_the_score():
    w = make_weights({"ransomware": (10, 0)})
    delta, explanation = w.adjustment(["ransomware"])
    assert delta > 0 and "ransomware" in explanation


def test_negative_votes_decrease_the_score():
    w = make_weights({"phishing": (0, 10)})
    delta, _ = w.adjustment(["phishing"])
    assert delta < 0


def test_split_votes_yield_a_weak_adjustment():
    w = make_weights({"patch": (5, 5)})
    delta, _ = w.adjustment(["patch"])
    assert delta == 0


def test_confidence_grows_with_the_number_of_votes():
    """20 unanimous votes should carry more weight than 3 unanimous votes."""
    few = make_weights({"malware": (3, 0)})
    many = make_weights({"malware": (30, 0)})
    assert many.adjustment(["malware"])[0] > few.adjustment(["malware"])[0]


# --------------------------------------------------------------------------- #
# Guardrails
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("factual", ["kev", "epss", "cve", "cvss"])
def test_factual_signals_never_adjusted(factual):
    """
    Core guardrail: a vote expresses taste, not fact. KEV says a
    vulnerability is exploited — no 👎 can make that false.
    """
    w = make_weights({factual: (0, 50)})
    delta, _ = w.adjustment([factual])
    assert delta == 0


def test_adjustment_capped_per_signal():
    w = make_weights({"ransomware": (1000, 0)}, max_adjustment=4)
    delta, _ = w.adjustment(["ransomware"])
    assert delta <= 4


def test_stacked_signals_capped_globally():
    """Ten positive signals must not produce a +40 adjustment."""
    w = make_weights({f"s{i}": (50, 0) for i in range(10)}, max_adjustment=4)
    delta, _ = w.adjustment([f"s{i}" for i in range(10)])
    assert delta <= 8


def test_unknown_signal_ignored():
    w = make_weights({"ransomware": (10, 0)})
    delta, _ = w.adjustment(["never-seen-signal"])
    assert delta == 0


def test_source_adjusted_separately():
    w = make_weights(sources={"SecurityWeek": (0, 12)})
    delta, explanation = w.adjustment([], source="SecurityWeek")
    assert delta < 0 and "SecurityWeek" in explanation


# --------------------------------------------------------------------------- #
# Collection from Discord history
# --------------------------------------------------------------------------- #
class FakeReaction:
    def __init__(self, emoji, count, me=False):
        self.emoji, self.count, self.me = emoji, count, me


class FakeEmbed:
    def __init__(self, url, footer, author=None):
        self.url = url
        self.footer = types.SimpleNamespace(text=footer)
        self.author = types.SimpleNamespace(name=author) if author else None


class FakeMessage:
    def __init__(self, embeds, reactions):
        self.embeds, self.reactions = embeds, reactions


class FakeChannel:
    def __init__(self, messages):
        self._messages = messages

    def history(self, limit=None, after=None):
        async def gen():
            for message in self._messages:
                yield message
        return gen()


async def _collect(messages, **kw):
    return await fb.collect_feedback(FakeChannel(messages), **kw)


@pytest.mark.asyncio
async def test_collection_aggregates_votes():
    messages = [
        FakeMessage(
            [FakeEmbed("https://ex.com/1", "Score 20 · sig:ransomware,rce",
                       "BleepingComputer · Title")],
            [FakeReaction(fb.UPVOTE, 3), FakeReaction(fb.DOWNVOTE, 1)],
        ),
    ]
    w = await _collect(messages)
    assert w.signals["ransomware"].up == 3
    assert w.signals["ransomware"].down == 1
    assert w.sources["BleepingComputer"].up == 3
    assert w.articles_voted == 1


@pytest.mark.asyncio
async def test_bots_own_reaction_not_counted():
    """The bot pre-posts 👍/👎: its own reaction must not count as a vote."""
    messages = [
        FakeMessage(
            [FakeEmbed("https://ex.com/1", "sig:phishing")],
            [FakeReaction(fb.UPVOTE, 1, me=True), FakeReaction(fb.DOWNVOTE, 1, me=True)],
        ),
    ]
    w = await _collect(messages)
    assert w.votes_seen == 0
    assert not w.signals


@pytest.mark.asyncio
async def test_other_emojis_ignored():
    """🔖 or 👀 remain free for personal use."""
    messages = [
        FakeMessage(
            [FakeEmbed("https://ex.com/1", "sig:phishing")],
            [FakeReaction("🔖", 5), FakeReaction("👀", 2)],
        ),
    ]
    w = await _collect(messages)
    assert w.votes_seen == 0


@pytest.mark.asyncio
async def test_messages_without_reactions_ignored():
    messages = [FakeMessage([FakeEmbed("https://ex.com/1", "sig:rce")], [])]
    w = await _collect(messages)
    assert w.articles_voted == 0


@pytest.mark.asyncio
async def test_digest_headers_ignored():
    """An embed with no URL is a header, not an article."""
    messages = [
        FakeMessage(
            [FakeEmbed(None, "Summaries: gemini · Daily digest")],
            [FakeReaction(fb.UPVOTE, 4)],
        ),
    ]
    w = await _collect(messages)
    assert w.articles_voted == 0


@pytest.mark.asyncio
async def test_collection_never_raises():
    """An unavailable Discord API degrades the ranking, doesn't stop the watch."""
    class Broken:
        def history(self, limit=None, after=None):
            async def gen():
                raise RuntimeError("403 Forbidden")
                yield  # pragma: no cover
            return gen()

    w = await fb.collect_feedback(Broken())
    assert w.votes_seen == 0
    assert not w.is_active