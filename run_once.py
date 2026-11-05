#!/usr/bin/env python3
"""
One watch cycle, then exit. Meant for a scheduler (GitHub Actions).

Talks to Discord over REST only: no gateway, so nothing has to stay online.
Publishing, history reads and reactions all work this way; slash commands
don't, they need bot.py.

    python run_once.py
    python run_once.py --dry-run            # reads Discord, never writes
    python run_once.py --offline            # no Discord at all, for local tests
    python run_once.py --force-digest

Exit code 1 means the cycle failed, 2 that the configuration is invalid: the
scheduler reports both.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
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


def write_run_summary(report: dict, failed_feeds: list[str], mode: str) -> None:
    """
    Shows what the run did on its GitHub page.

    A green run only says nothing crashed. Without this, a run that published
    nothing looks exactly like one that published the digest.
    """
    path = os.getenv("GITHUB_STEP_SUMMARY")
    if not path:
        return
    rows = [
        ("Mode", mode),
        ("Articles fetched", report["fetched"]),
        ("New candidates", report["queued"]),
        ("Published", report["posted"]),
        ("Urgent alerts", report["urgent"]),
        ("KEV escalations", report["kev_escalations"]),
        ("Deferred (AI unavailable)", report["deferred"]),
        ("Failed feeds", ", ".join(failed_feeds) or "none"),
    ]
    lines = ["| | |", "|---|---|", *(f"| {name} | {value} |" for name, value in rows)]
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


async def run(dry_run: bool, force_digest: bool, offline: bool = False) -> int:
    pipeline = Pipeline(settings)

    try:
        if offline:
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

    mode = "offline" if offline else "dry run" if dry_run else "live"
    write_run_summary(report, pipeline.failed_feeds, mode)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Runs one CyberWatch cycle.")
    parser.add_argument("--dry-run", action="store_true", help="read Discord, never write")
    parser.add_argument("--offline", action="store_true", help="skip Discord entirely")
    parser.add_argument("--force-digest", action="store_true", help="send the digest now")
    args = parser.parse_args()

    problems = settings.validate()
    # Only --offline may run without Discord credentials: a dry run exists to
    # prove they work, so it must not pass without them.
    if args.offline:
        problems = [p for p in problems if not p.startswith("DISCORD_")]
    if problems:
        print("Invalid configuration:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 2

    for warning in settings.warnings():
        log.warning(warning)

    return asyncio.run(run(args.dry_run, args.force_digest, args.offline))


if __name__ == "__main__":
    sys.exit(main())
