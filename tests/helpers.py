"""Stand-ins for Discord objects, shared by the tests."""

from __future__ import annotations

import types
from dataclasses import replace
from datetime import datetime, timezone

import discord

from config import settings


def make_settings(**overrides):
    """Real settings, isolated from the local .env and from the network."""
    base = {
        "ai_provider": "none",
        "feeds": [],
        "fetch_fulltext": False,
        "enable_feedback": False,
        "enable_urgent": True,
        "enable_kev_retro_check": True,
        "ai_delay_seconds": 0,
        "digest_hour": 8,
        "digest_min_articles": 2,
        "daily_quota": 4,
        "digest_floor_score": 7,
        "min_score": 5,
        "urgent_daily_max": 2,
        "kev_retro_max_per_day": 3,
        "feed_failure_threshold": 3,
        "timezone_name": "UTC",
        "urgent_mention": "none",
    }
    return replace(settings, **{**base, **overrides})


def message(embed: discord.Embed, created_at: datetime | None = None):
    return types.SimpleNamespace(
        embeds=[embed],
        created_at=created_at or datetime.now(tz=timezone.utc),
        reactions=[],
    )


class SentMessage:
    async def add_reaction(self, emoji) -> None:
        pass


class FakeChannel:
    """Records what is sent, and replays it as history like Discord would."""

    def __init__(self, messages=None, fail_history: bool = False, fail_send: bool = False):
        self.messages = list(messages or [])
        self.fail_history = fail_history
        self.fail_send = fail_send
        self.sent: list[discord.Embed] = []

    def history(self, **kwargs):
        async def generate():
            if self.fail_history:
                raise RuntimeError("history unavailable")
            for item in reversed(self.messages):
                yield item

        return generate()

    async def send(self, content=None, embed=None, **kwargs):
        if self.fail_send:
            raise discord.HTTPException(
                types.SimpleNamespace(status=500, reason="boom"), "boom"
            )
        self.sent.append(embed)
        self.messages.append(message(embed))
        return SentMessage()
