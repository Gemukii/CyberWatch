#!/usr/bin/env python3
"""
One watch cycle, then exit. Meant for a scheduler (GitHub Actions).

Talks to Discord over REST only: no gateway, so nothing has to stay online.
Publishing, history reads and reactions all work this way; slash commands
don't, they need bot.py.

    python run_once.py
    python run_once.py --dry-run            # never writes to Discord
    python run_once.py --force-digest

Exit code 1 means the cycle failed, so the scheduler reports it.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

import discord

from config import settings
from pipeline import Pipeline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)-12s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("cyberwatch")
logging.getLogger("discord").setLevel(logging.WARNING)


class PrimingError(RuntimeError):
    """Discord history couldn't be read: publishing would repeat articles."""


class _SentMessage:
    async def add_reaction(self, emoji) -> None:
        pass


class DryRunChannel:
    """Reads through to the real channel, if any, and swallows every write."""

    def __init__(self, inner=None):
        self.inner = inner
        self.sent: list = []

    def history(self, **kwargs):
        if self.inner is not None:
            return self.inner.history(**kwargs)
        return _no_history()

    async def send(self, content=None, embed=None, **kwargs) -> _SentMessage:
        self.sent.append(embed)
        log.info("[dry-run] would send: %s", embed.title if embed else content)
        return _SentMessage()


async def _no_history():
    return
    yield  # makes this an async generator


async def run_with_channel(pipeline: Pipeline, channel, force_digest: bool) -> dict:
    """Rebuilds state from history, then runs the cycle. Fails closed."""
    await pipeline.state.prime_from_channel(
        channel, limit=pipeline.settings.history_limit, budget=pipeline.budget
    )
    # prime_from_channel() swallows read errors, which suits a resident bot.
    # Here every run starts empty, so carrying on would publish again
    # everything from the retention window.
    if not pipeline.state.primed:
        raise PrimingError("Could not read Discord history: nothing published this run")
    return await pipeline.run_cycle(channel, force_digest=force_digest)


async def run(dry_run: bool, force_digest: bool) -> int:
    pipeline = Pipeline(settings)

    try:
        if dry_run and not settings.discord_token:
            report = await run_with_channel(pipeline, DryRunChannel(), force_digest)
        else:
            # Intents only matter to the gateway, which is never opened.
            client = discord.Client(intents=discord.Intents.none())
            async with client:
                await client.login(settings.discord_token)
                channel = await client.fetch_channel(settings.channel_id)
                if dry_run:
                    channel = DryRunChannel(channel)
                report = await run_with_channel(pipeline, channel, force_digest)
    except Exception:
        log.exception("Run failed")
        return 1

    if report["error"]:
        log.error("Cycle failed: %s", report["error"])
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Runs one CyberWatch cycle.")
    parser.add_argument("--dry-run", action="store_true", help="never write to Discord")
    parser.add_argument("--force-digest", action="store_true", help="send the digest now")
    args = parser.parse_args()

    problems = settings.validate()
    if args.dry_run:
        problems = [p for p in problems if not p.startswith("DISCORD_")]
    if problems:
        print("Invalid configuration:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 2

    for warning in settings.warnings():
        log.warning(warning)

    return asyncio.run(run(args.dry_run, args.force_digest))


if __name__ == "__main__":
    sys.exit(main())
